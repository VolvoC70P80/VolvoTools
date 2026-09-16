#include <common/CarPlatform.hpp>
#include <common/ICanChannel.hpp>
#include <common/J2534ChannelProvider.hpp>
#include <common/Util.hpp>
#include <common/protocols/D2Messages.hpp>
#include <common/protocols/D2Request.hpp>

#include <j2534/J2534.hpp>

#include <easylogging++.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

INITIALIZE_EASYLOGGINGPP

namespace {

constexpr uint32_t kEcuId = 0x7A;
constexpr uint32_t kDefaultStart = 0x800000;
constexpr uint32_t kDefaultSize = 0x100;
constexpr uint32_t kMaxAddressExclusive = 0x1000000; // D2 0xBB uses a 24-bit address.
constexpr uint32_t kChunkSize = 8;

uint32_t parseHex(const char* value)
{
    size_t consumed = 0;
    const unsigned long parsed = std::stoul(value, &consumed, 16);
    if (consumed != std::string(value).size()) {
        throw std::runtime_error(std::string("Invalid hex value: ") + value);
    }
    return static_cast<uint32_t>(parsed);
}

void printUsage(const char* exe)
{
    std::cout
        << "Read-only Volvo P80 ME7 memory reader (D2 service 0xBB)\n\n"
        << "Usage:\n  " << exe << " [output.bin] [start_hex] [size_hex]\n\n"
        << "Defaults:\n"
        << "  output.bin = c70_read_test.bin\n"
        << "  start_hex  = 800000\n"
        << "  size_hex   = 100 (256 bytes)\n\n"
        << "This tool contains NO flash/erase/write commands.\n";
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        common::initLogger("c70_reader.log", true, true);

        if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            printUsage(argv[0]);
            return 0;
        }

        const std::string outputPath = argc > 1 ? argv[1] : "c70_read_test.bin";
        const uint32_t start = argc > 2 ? parseHex(argv[2]) : kDefaultStart;
        const uint32_t size = argc > 3 ? parseHex(argv[3]) : kDefaultSize;

        if (size == 0) {
            throw std::runtime_error("Read size must be greater than zero");
        }
        if (start >= kMaxAddressExclusive || size > kMaxAddressExclusive - start) {
            throw std::runtime_error("Requested range is outside the 24-bit D2 address space");
        }

        const auto devices = common::getAvailableDevices();
        const auto deviceIt = std::find_if(devices.begin(), devices.end(), [](const auto& device) {
            return device.deviceName.find("GODIAG") != std::string::npos;
        });

        if (deviceIt == devices.end()) {
            std::cerr << "GODIAG J2534 device not found. Available devices:\n";
            for (const auto& device : devices) {
                std::cerr << "  " << device.deviceName << "\n";
            }
            return 2;
        }

        std::cout << "Device: " << deviceIt->deviceName << "\n";
        std::cout << "Platform: P80, ECU: 0x7A\n";
        std::cout << "Read range: 0x" << std::hex << std::uppercase << start
                  << " - 0x" << (start + size - 1)
                  << " (0x" << size << " bytes)\n" << std::dec;
        std::cout << "Opening J2534...\n";

        auto j2534 = std::make_unique<j2534::J2534>(deviceIt->libraryName);
        j2534->PassThruOpen("");

        // Use the same P80 channel selection path as VolvoLogger, which is known
        // to work with this car/interface. Only the ECM channel is requested.
        common::J2534ChannelProvider channelProvider(*j2534, common::CarPlatform::P80);
        auto channel = channelProvider.getChannelForEcu(kEcuId);
        if (!channel) {
            throw std::runtime_error("Could not open the P80 ECM CAN channel");
        }

        std::vector<uint8_t> data;
        data.reserve(size);

        std::cout << "Reading via D2 service 0xBB...\n";
        for (uint32_t offset = 0; offset < size; offset += kChunkSize) {
            const uint32_t currentAddress = start + offset;
            const uint32_t chunk = std::min(kChunkSize, size - offset);

            channel->clearRx();
            channel->clearTx();

            common::D2Request request{
                common::D2Messages::createReadDataByAddrMsg(
                    static_cast<uint8_t>(kEcuId),
                    currentAddress,
                    static_cast<uint8_t>(chunk))
            };

            const auto response = request.process(*channel, 1500);
            if (response.size() < chunk) {
                std::ostringstream error;
                error << "Short response at 0x" << std::hex << std::uppercase << currentAddress
                      << ": got " << std::dec << response.size()
                      << " bytes, expected " << chunk;
                throw std::runtime_error(error.str());
            }

            data.insert(data.end(), response.begin(), response.begin() + chunk);

            const uint32_t done = offset + chunk;
            if (done == size || (done % 0x100) == 0) {
                std::cout << "  " << std::dec << done << "/" << size << " bytes\n";
            }
        }

        std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw std::runtime_error("Could not create output file: " + outputPath);
        }
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!output) {
            throw std::runtime_error("Failed while writing output file");
        }

        std::cout << "SUCCESS: saved " << data.size() << " bytes to " << outputPath << "\n";
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    catch (...) {
        std::cerr << "ERROR: unknown exception\n";
        return 1;
    }
}
