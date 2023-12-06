#include <iostream>
#include <string_view>
#include <unistd.h>

// Never called
void callme() {
    system("/bin/sh");
    asm volatile (
      "pop %rdi\n"
      "ret");
}

// Trims last new line characters if they are presented
std::string_view trim(std::string_view str) {
    if (const auto pos = str.find('\n'); pos != std::string_view::npos) {
        str.remove_suffix(str.size() - pos);
    }
    return str;
}

bool auth() {
    char requiredPassword[] {"1111111111"};
    char enteredPassword[20] {0};

    std::cout << "Enter a password: " << std::endl;

    // WARNING, UNSAFE!
    read(0, enteredPassword, 200);

    return trim(enteredPassword) == requiredPassword;
}

int main(int argc, char *argv[]) {
    const auto status{auth()};
    status ? std::cout << "Authentication SUCCEEDED" << std::endl
           : std::cout << "Authentication FAILED" << std::endl;
    return 0;
}