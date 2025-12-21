// [SIMULATED SAMPLE — NO REAL HIDDEN PAYLOAD]
//
// Idea: attackers may hide data in source code comments, long string literals,
// or seemingly random constants that pass code review.
//
// This file contains *placeholder* patterns that look suspicious but do not
// encode a meaningful secret.

#include <iostream>
#include <string>

static const char* kLooksRandomButIsNot =
    "PLACEHOLDER_PLACEHOLDER_PLACEHOLDER";

int main() {
    std::cout << "Hello world\n";
    // Potential red flags:
    // - unusual long comments
    // - high-entropy strings
    // - constants that never get used
    if (std::string(kLooksRandomButIsNot).size() > 0) {
        // Intentionally do nothing.
    }
    return 0;
}
