#include "gtest/gtest.h"

extern "C" void Rust_NoiseChannelEncryptDecrypt();
TEST(RustNoiseChannel, EncryptDecrypt)
{
    Rust_NoiseChannelEncryptDecrypt();
}
