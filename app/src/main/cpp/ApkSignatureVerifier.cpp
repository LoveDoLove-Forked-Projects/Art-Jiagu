#include "ApkSignatureVerifier.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {
constexpr uint32_t kApkSignatureSchemeV2BlockId = 0x7109871aU;
constexpr uint32_t kApkSignatureSchemeV3BlockId = 0xf05368c0U;
constexpr size_t kEocdMinSize = 22;
constexpr size_t kMaxEocdSearch = 0xffff + kEocdMinSize;
constexpr char kSigningBlockMagic[] = "APK Sig Block 42";

uint32_t ReadU32(const uint8_t *data) {
    return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8U) |
           (static_cast<uint32_t>(data[2]) << 16U) | (static_cast<uint32_t>(data[3]) << 24U);
}

uint16_t ReadU16(const uint8_t *data) {
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8U);
}

uint64_t ReadU64(const uint8_t *data) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value |= static_cast<uint64_t>(data[i]) << (i * 8U);
    return value;
}

bool ReadLengthPrefixed(const uint8_t *data, size_t limit, size_t *offset,
                        const uint8_t **value, size_t *length) {
    if (data == nullptr || offset == nullptr || value == nullptr || length == nullptr ||
        *offset > limit || limit - *offset < 4) return false;
    const uint32_t size = ReadU32(data + *offset);
    *offset += 4;
    if (size > limit - *offset) return false;
    *value = data + *offset;
    *length = size;
    *offset += size;
    return true;
}

bool RawReadAt(int fd, uint64_t offset, void *buffer, size_t length) {
    auto *bytes = static_cast<uint8_t *>(buffer);
    size_t done = 0;
    while (done < length) {
        const ssize_t count = static_cast<ssize_t>(syscall(__NR_pread64, fd, bytes + done,
                                                            length - done, offset + done));
        if (count <= 0) return false;
        done += static_cast<size_t>(count);
    }
    return true;
}

class Sha256 {
public:
    Sha256() { Reset(); }
    void Update(const uint8_t *data, size_t length) {
        if (data == nullptr) return;
        total_ += length;
        while (length > 0) {
            const size_t take = length < (64 - used_) ? length : (64 - used_);
            memcpy(block_.data() + used_, data, take);
            used_ += take;
            data += take;
            length -= take;
            if (used_ == 64) { Transform(block_.data()); used_ = 0; }
        }
    }
    std::array<uint8_t, 32> Final() {
        const uint64_t bits = total_ * 8U;
        const uint8_t marker = 0x80;
        Update(&marker, 1);
        const uint8_t zero = 0;
        while (used_ != 56) Update(&zero, 1);
        uint8_t lengthBytes[8]{};
        for (size_t i = 0; i < 8; ++i) lengthBytes[7 - i] = static_cast<uint8_t>(bits >> (i * 8U));
        Update(lengthBytes, sizeof(lengthBytes));
        std::array<uint8_t, 32> digest{};
        for (size_t i = 0; i < state_.size(); ++i) {
            digest[i * 4] = static_cast<uint8_t>(state_[i] >> 24U);
            digest[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16U);
            digest[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8U);
            digest[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        return digest;
    }
private:
    static uint32_t RotateRight(uint32_t value, uint32_t count) {
        return (value >> count) | (value << (32U - count));
    }
    void Reset() {
        state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                  0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
        total_ = 0; used_ = 0;
    }
    void Transform(const uint8_t *block) {
        static constexpr uint32_t k[] = {
                0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
                0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
                0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
                0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
                0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
                0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
                0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
                0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
        uint32_t words[64]{};
        for (size_t i = 0; i < 16; ++i) words[i] = (static_cast<uint32_t>(block[i * 4]) << 24U) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16U) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8U) | block[i * 4 + 3];
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t s0 = RotateRight(words[i - 15], 7) ^ RotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3U);
            const uint32_t s1 = RotateRight(words[i - 2], 17) ^ RotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10U);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        uint32_t a=state_[0], b=state_[1], c=state_[2], d=state_[3], e=state_[4], f=state_[5], g=state_[6], h=state_[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t temp1 = h + s1 + choose + k[i] + words[i];
            const uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + majority;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }
    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> block_{};
    uint64_t total_{};
    size_t used_{};
};

bool ExtractFirstCertificateSha256(const std::vector<uint8_t> &signers, uint8_t outSha256[32]) {
    size_t outerOffset = 0, signerOffset = 0, signedDataOffset = 0;
    size_t certificatesOffset = 0, certificateOffset = 0;
    const uint8_t *outer = nullptr, *signer = nullptr, *signedData = nullptr, *digests = nullptr, *certificates = nullptr, *certificate = nullptr;
    size_t outerLength = 0, signerLength = 0, signedDataLength = 0, ignoredLength = 0, certificatesLength = 0, certificateLength = 0;
    if (!ReadLengthPrefixed(signers.data(), signers.size(), &outerOffset, &outer, &outerLength) || outerOffset != signers.size() ||
        !ReadLengthPrefixed(outer, outerLength, &signerOffset, &signer, &signerLength) || signerOffset != outerLength ||
        !ReadLengthPrefixed(signer, signerLength, &signedDataOffset, &signedData, &signedDataLength) ||
        !ReadLengthPrefixed(signedData, signedDataLength, &certificatesOffset, &digests, &ignoredLength) ||
        !ReadLengthPrefixed(signedData, signedDataLength, &certificatesOffset, &certificates, &certificatesLength) ||
        !ReadLengthPrefixed(certificates, certificatesLength, &certificateOffset, &certificate, &certificateLength)) return false;
    
    Sha256 hash;
    hash.Update(certificate, certificateLength);
    const auto digest = hash.Final();
    memcpy(outSha256, digest.data(), 32);
    return true;
}

bool ReadSigningBlockSha256FromFile(const std::string &apkPath, uint8_t outSha256[32]) {
    const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, apkPath.c_str(), O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return false;
    struct stat statInfo{};
    const bool statOk = fstat(fd, &statInfo) == 0 && statInfo.st_size >= static_cast<off_t>(kEocdMinSize);
    if (!statOk) { close(fd); return false; }
    const uint64_t fileSize = static_cast<uint64_t>(statInfo.st_size);
    const size_t tailSize = static_cast<size_t>(fileSize < kMaxEocdSearch ? fileSize : kMaxEocdSearch);
    std::vector<uint8_t> tail(tailSize);
    if (!RawReadAt(fd, fileSize - tailSize, tail.data(), tail.size())) { close(fd); return false; }
    size_t eocd = tail.size() - kEocdMinSize;
    bool found = false;
    for (;;) {
        if (ReadU32(tail.data() + eocd) == 0x06054b50U &&
            eocd + kEocdMinSize + ReadU16(tail.data() + eocd + 20) == tail.size()) {
            found = true;
            break;
        }
        if (eocd == 0) break;
        --eocd;
    }
    if (!found) { close(fd); return false; }
    const uint64_t centralDirectoryOffset = ReadU32(tail.data() + eocd + 16);
    if (centralDirectoryOffset < 24 || centralDirectoryOffset >= fileSize) { close(fd); return false; }
    uint8_t footer[24]{};
    if (!RawReadAt(fd, centralDirectoryOffset - sizeof(footer), footer, sizeof(footer)) ||
        memcmp(footer + 8, kSigningBlockMagic, sizeof(kSigningBlockMagic) - 1) != 0) { close(fd); return false; }
    const uint64_t blockSize = ReadU64(footer);
    if (blockSize < 24 || blockSize > centralDirectoryOffset - 8 || blockSize > 16U * 1024U * 1024U) { close(fd); return false; }
    const uint64_t blockOffset = centralDirectoryOffset - (blockSize + 8);
    std::vector<uint8_t> block(static_cast<size_t>(blockSize + 8));
    if (!RawReadAt(fd, blockOffset, block.data(), block.size()) || ReadU64(block.data()) != blockSize) { close(fd); return false; }
    close(fd);
    size_t offset = 8;
    const size_t entriesEnd = block.size() - 24;
    const uint8_t *v2 = nullptr, *v3 = nullptr;
    size_t v2Length = 0, v3Length = 0;
    while (offset < entriesEnd) {
        if (entriesEnd - offset < 12) return false;
        const uint64_t length = ReadU64(block.data() + offset);
        offset += 8;
        if (length < 4 || length > entriesEnd - offset) return false;
        const uint32_t id = ReadU32(block.data() + offset);
        const uint8_t *value = block.data() + offset + 4;
        const size_t valueLength = static_cast<size_t>(length - 4);
        if (id == kApkSignatureSchemeV3BlockId) { v3 = value; v3Length = valueLength; }
        if (id == kApkSignatureSchemeV2BlockId) { v2 = value; v2Length = valueLength; }
        offset += static_cast<size_t>(length);
    }
    if (offset != entriesEnd) return false;
    if (v3 != nullptr && ExtractFirstCertificateSha256(std::vector<uint8_t>(v3, v3 + v3Length), outSha256)) return true;
    return v2 != nullptr && ExtractFirstCertificateSha256(std::vector<uint8_t>(v2, v2 + v2Length), outSha256);
}

bool ExtractSha256ContentDigest(const uint8_t *signers, size_t signersLength, uint8_t outDigest[32]) {
    size_t outerOffset = 0, signerOffset = 0, signedDataOffset = 0, digestOffset = 0;
    const uint8_t *outer = nullptr, *signer = nullptr, *signedData = nullptr, *digests = nullptr;
    size_t outerLength = 0, signerLength = 0, signedDataLength = 0, digestsLength = 0;
    if (!ReadLengthPrefixed(signers, signersLength, &outerOffset, &outer, &outerLength) || outerOffset != signersLength ||
        !ReadLengthPrefixed(outer, outerLength, &signerOffset, &signer, &signerLength) || signerOffset != outerLength ||
        !ReadLengthPrefixed(signer, signerLength, &signedDataOffset, &signedData, &signedDataLength) ||
        !ReadLengthPrefixed(signedData, signedDataLength, &digestOffset, &digests, &digestsLength)) return false;
    size_t offset = 0;
    while (offset < digestsLength) {
        const uint8_t *record = nullptr; size_t recordLength = 0;
        if (!ReadLengthPrefixed(digests, digestsLength, &offset, &record, &recordLength) || recordLength < 8) return false;
        const uint32_t algorithm = ReadU32(record);
        size_t digestValueOffset = 4; const uint8_t *digest = nullptr; size_t digestLength = 0;
        if (!ReadLengthPrefixed(record, recordLength, &digestValueOffset, &digest, &digestLength) || digestValueOffset != recordLength) return false;
        if (digestLength == 32 && (algorithm == 0x0101U || algorithm == 0x0103U || algorithm == 0x0104U || algorithm == 0x0421U)) {
            memcpy(outDigest, digest, 32); return true;
        }
    }
    return false;
}

const char *JcaKeyAlgorithm(uint32_t scheme) {
    switch (scheme) { case 0x0101U: case 0x0102U: case 0x0421U: case 0x0422U: return "RSA"; case 0x0103U: case 0x0104U: return "EC"; case 0x0105U: case 0x0106U: return "DSA"; default: return nullptr; }
}

const char *JcaSignatureAlgorithm(uint32_t scheme) {
    switch (scheme) {
        case 0x0101U: return "SHA256withRSA"; case 0x0102U: return "SHA512withRSA";
        case 0x0103U: return "SHA256withECDSA"; case 0x0104U: return "SHA512withECDSA";
        case 0x0105U: return "SHA256withDSA"; case 0x0106U: return "SHA512withDSA";
        case 0x0421U: return "SHA256withRSA/PSS"; case 0x0422U: return "SHA512withRSA/PSS";
        default: return nullptr;
    }
}

bool VerifySignerSignature(JNIEnv *env, const uint8_t *signers, size_t signersLength) {
    if (env == nullptr) return false;
    size_t outerOffset = 0, signerOffset = 0, signerFieldsOffset = 0, signatureOffset = 0, keyOffset = 0;
    const uint8_t *outer = nullptr, *signer = nullptr, *signedData = nullptr, *signatures = nullptr, *publicKey = nullptr;
    size_t outerLength = 0, signerLength = 0, signedDataLength = 0, signaturesLength = 0, publicKeyLength = 0;
    if (!ReadLengthPrefixed(signers, signersLength, &outerOffset, &outer, &outerLength) || outerOffset != signersLength ||
        !ReadLengthPrefixed(outer, outerLength, &signerOffset, &signer, &signerLength) || signerOffset != outerLength ||
        !ReadLengthPrefixed(signer, signerLength, &signerFieldsOffset, &signedData, &signedDataLength) ||
        !ReadLengthPrefixed(signer, signerLength, &signerFieldsOffset, &signatures, &signaturesLength) ||
        !ReadLengthPrefixed(signer, signerLength, &signerFieldsOffset, &publicKey, &publicKeyLength)) return false;
    uint32_t scheme = 0; const uint8_t *signature = nullptr; size_t signatureLength = 0;
    while (signatureOffset < signaturesLength) {
        const uint8_t *record = nullptr; size_t recordLength = 0;
        if (!ReadLengthPrefixed(signatures, signaturesLength, &signatureOffset, &record, &recordLength) || recordLength < 8) return false;
        const uint32_t candidate = ReadU32(record); size_t offset = 4; const uint8_t *value = nullptr; size_t length = 0;
        if (!ReadLengthPrefixed(record, recordLength, &offset, &value, &length) || offset != recordLength) return false;
        if (JcaSignatureAlgorithm(candidate) != nullptr) { scheme = candidate; signature = value; signatureLength = length; break; }
    }
    const char *keyAlgorithm = JcaKeyAlgorithm(scheme); const char *signatureAlgorithm = JcaSignatureAlgorithm(scheme);
    if (keyAlgorithm == nullptr || signatureAlgorithm == nullptr) return false;
    jclass specClass = env->FindClass("java/security/spec/X509EncodedKeySpec"); jclass keyFactoryClass = env->FindClass("java/security/KeyFactory"); jclass signatureClass = env->FindClass("java/security/Signature");
    if (specClass == nullptr || keyFactoryClass == nullptr || signatureClass == nullptr) { env->ExceptionClear(); return false; }
    jbyteArray keyBytes = env->NewByteArray(static_cast<jsize>(publicKeyLength)); jbyteArray signedBytes = env->NewByteArray(static_cast<jsize>(signedDataLength)); jbyteArray signatureBytes = env->NewByteArray(static_cast<jsize>(signatureLength));
    if (keyBytes == nullptr || signedBytes == nullptr || signatureBytes == nullptr) return false;
    env->SetByteArrayRegion(keyBytes, 0, static_cast<jsize>(publicKeyLength), reinterpret_cast<const jbyte *>(publicKey)); env->SetByteArrayRegion(signedBytes, 0, static_cast<jsize>(signedDataLength), reinterpret_cast<const jbyte *>(signedData)); env->SetByteArrayRegion(signatureBytes, 0, static_cast<jsize>(signatureLength), reinterpret_cast<const jbyte *>(signature));
    jmethodID specInit = env->GetMethodID(specClass, "<init>", "([B)V"); jobject spec = env->NewObject(specClass, specInit, keyBytes);
    jmethodID factoryGet = env->GetStaticMethodID(keyFactoryClass, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyFactory;"); jstring keyName = env->NewStringUTF(keyAlgorithm); jobject factory = env->CallStaticObjectMethod(keyFactoryClass, factoryGet, keyName);
    jmethodID generatePublic = env->GetMethodID(keyFactoryClass, "generatePublic", "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;"); jobject publicKeyObject = env->CallObjectMethod(factory, generatePublic, spec);
    jmethodID signatureGet = env->GetStaticMethodID(signatureClass, "getInstance", "(Ljava/lang/String;)Ljava/security/Signature;"); jstring signatureName = env->NewStringUTF(signatureAlgorithm); jobject verifier = env->CallStaticObjectMethod(signatureClass, signatureGet, signatureName);
    jmethodID initVerify = env->GetMethodID(signatureClass, "initVerify", "(Ljava/security/PublicKey;)V"); jmethodID update = env->GetMethodID(signatureClass, "update", "([B)V"); jmethodID verify = env->GetMethodID(signatureClass, "verify", "([B)Z");
    env->CallVoidMethod(verifier, initVerify, publicKeyObject); env->CallVoidMethod(verifier, update, signedBytes); const jboolean verified = env->CallBooleanMethod(verifier, verify, signatureBytes);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return verified == JNI_TRUE;
}

bool HashChunk(int fd, uint64_t offset, uint32_t length, std::array<uint8_t, 32> *out) {
    Sha256 hash; const uint8_t marker = 0xa5; uint8_t size[4] = {
            static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8U),
            static_cast<uint8_t>(length >> 16U), static_cast<uint8_t>(length >> 24U)};
    hash.Update(&marker, 1); hash.Update(size, sizeof(size));
    std::array<uint8_t, 64 * 1024> buffer{};
    uint64_t cursor = offset; uint32_t remaining = length;
    while (remaining > 0) {
        const size_t take = remaining < buffer.size() ? remaining : buffer.size();
        if (!RawReadAt(fd, cursor, buffer.data(), take)) return false;
        hash.Update(buffer.data(), take); cursor += take; remaining -= static_cast<uint32_t>(take);
    }
    *out = hash.Final(); return true;
}

bool HashMemoryChunk(const uint8_t *data, uint32_t length, std::array<uint8_t, 32> *out) {
    if (data == nullptr) return false;
    Sha256 hash; const uint8_t marker = 0xa5; uint8_t size[4] = {
            static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8U),
            static_cast<uint8_t>(length >> 16U), static_cast<uint8_t>(length >> 24U)};
    hash.Update(&marker, 1); hash.Update(size, sizeof(size)); hash.Update(data, length); *out = hash.Final(); return true;
}

bool VerifyContentDigestFromFile(JNIEnv *env, const std::string &apkPath) {
    const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, apkPath.c_str(), O_RDONLY | O_CLOEXEC, 0));
    struct stat statInfo{}; if (fd < 0 || fstat(fd, &statInfo) != 0 || statInfo.st_size < static_cast<off_t>(kEocdMinSize)) { if (fd >= 0) close(fd); return false; }
    const uint64_t fileSize = static_cast<uint64_t>(statInfo.st_size); const size_t tailSize = static_cast<size_t>(fileSize < kMaxEocdSearch ? fileSize : kMaxEocdSearch);
    std::vector<uint8_t> tail(tailSize); if (!RawReadAt(fd, fileSize - tailSize, tail.data(), tailSize)) { close(fd); return false; }
    size_t eocdInTail = tailSize - kEocdMinSize; bool found = false;
    for (;;) { if (ReadU32(tail.data() + eocdInTail) == 0x06054b50U && eocdInTail + kEocdMinSize + ReadU16(tail.data() + eocdInTail + 20) == tailSize) { found = true; break; } if (eocdInTail == 0) break; --eocdInTail; }
    if (!found) { close(fd); return false; }
    const uint64_t eocdOffset = fileSize - tailSize + eocdInTail; const uint64_t centralDirectoryOffset = ReadU32(tail.data() + eocdInTail + 16);
    uint8_t footer[24]{}; if (centralDirectoryOffset < 24 || !RawReadAt(fd, centralDirectoryOffset - 24, footer, 24) || memcmp(footer + 8, kSigningBlockMagic, sizeof(kSigningBlockMagic) - 1) != 0) { close(fd); return false; }
    const uint64_t blockSize = ReadU64(footer); const uint64_t blockOffset = centralDirectoryOffset - blockSize - 8;
    std::vector<uint8_t> block(static_cast<size_t>(blockSize + 8)); if (!RawReadAt(fd, blockOffset, block.data(), block.size())) { close(fd); return false; }
    const uint8_t *scheme = nullptr; size_t schemeLength = 0; size_t entryOffset = 8; const size_t entriesEnd = block.size() - 24;
    while (entryOffset < entriesEnd) { const uint64_t length = ReadU64(block.data() + entryOffset); entryOffset += 8; if (length < 4 || length > entriesEnd - entryOffset) { close(fd); return false; } const uint32_t id = ReadU32(block.data() + entryOffset); if (id == kApkSignatureSchemeV3BlockId || (scheme == nullptr && id == kApkSignatureSchemeV2BlockId)) { scheme = block.data() + entryOffset + 4; schemeLength = static_cast<size_t>(length - 4); } entryOffset += static_cast<size_t>(length); }
    uint8_t expected[32]{}; if (scheme == nullptr || !VerifySignerSignature(env, scheme, schemeLength) || !ExtractSha256ContentDigest(scheme, schemeLength, expected)) { close(fd); return false; }
    std::vector<std::array<uint8_t, 32>> chunks; const uint64_t chunkSize = 1024U * 1024U;
    auto appendSection = [&](uint64_t offset, uint64_t length) -> bool { while (length > 0) { const uint32_t take = static_cast<uint32_t>(length < chunkSize ? length : chunkSize); std::array<uint8_t, 32> digest{}; if (!HashChunk(fd, offset, take, &digest)) return false; chunks.push_back(digest); offset += take; length -= take; } return true; };
    bool ok = appendSection(0, blockOffset) && appendSection(centralDirectoryOffset, eocdOffset - centralDirectoryOffset);
    std::vector<uint8_t> eocd(tail.begin() + eocdInTail, tail.end()); if (eocd.size() < 20) ok = false; else { const uint32_t patched = static_cast<uint32_t>(blockOffset); eocd[16] = patched; eocd[17] = patched >> 8U; eocd[18] = patched >> 16U; eocd[19] = patched >> 24U; }
    if (ok) {
        std::array<uint8_t, 32> eocdDigest{};
        ok = HashMemoryChunk(eocd.data(), static_cast<uint32_t>(eocd.size()), &eocdDigest);
        chunks.push_back(eocdDigest);
        const uint8_t marker = 0x5a; const uint32_t chunkCount = static_cast<uint32_t>(chunks.size());
        uint8_t count[4] = {static_cast<uint8_t>(chunkCount), static_cast<uint8_t>(chunkCount >> 8U), static_cast<uint8_t>(chunkCount >> 16U), static_cast<uint8_t>(chunkCount >> 24U)};
        Sha256 root; root.Update(&marker, 1); root.Update(count, 4); for (const auto &chunk : chunks) root.Update(chunk.data(), chunk.size());
        const auto actual = root.Final(); ok = memcmp(actual.data(), expected, 32) == 0;
    }
    close(fd); return ok;
}

std::string GetSourceDirFromJni(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) return "";
    jclass contextClass = env->GetObjectClass(context);
    if (contextClass == nullptr) { env->ExceptionClear(); return ""; }
    jmethodID getApplicationInfo = env->GetMethodID(contextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (getApplicationInfo == nullptr) { env->ExceptionClear(); return ""; }
    jobject appInfo = env->CallObjectMethod(context, getApplicationInfo);
    if (env->ExceptionCheck() || appInfo == nullptr) { env->ExceptionClear(); return ""; }
    jclass appInfoClass = env->GetObjectClass(appInfo);
    if (appInfoClass == nullptr) { env->ExceptionClear(); return ""; }
    jfieldID sourceDir = env->GetFieldID(appInfoClass, "sourceDir", "Ljava/lang/String;");
    if (sourceDir == nullptr) { env->ExceptionClear(); return ""; }
    auto path = static_cast<jstring>(env->GetObjectField(appInfo, sourceDir));
    if (env->ExceptionCheck() || path == nullptr) { env->ExceptionClear(); return ""; }
    const char *chars = env->GetStringUTFChars(path, nullptr);
    if (chars == nullptr) return "";
    std::string result(chars);
    env->ReleaseStringUTFChars(path, chars);
    return result;
}

std::string GetSourceDirFromMaps() {
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return "";
    char buffer[4096];
    std::string cache;
    std::string foundPath;

    while (true) {
        ssize_t readSize = static_cast<ssize_t>(syscall(__NR_read, fd, buffer, sizeof(buffer)));
        if (readSize <= 0) break;
        cache.append(buffer, readSize);

        size_t pos;
        while ((pos = cache.find('\n')) != std::string::npos) {
            std::string line = cache.substr(0, pos);
            cache.erase(0, pos + 1);

            size_t slashPos = line.find("/data/app/");
            if (slashPos != std::string::npos) {
                std::string pathCandidate = line.substr(slashPos);
                if (pathCandidate.find(".apk") != std::string::npos) {
                    foundPath = pathCandidate;
                    break;
                }
            }
        }
        if (!foundPath.empty()) break;
    }
    syscall(__NR_close, fd);
    return foundPath;
}
} // namespace

bool ReadApkSigningBlockSha256(JNIEnv *env, jobject context, uint8_t outSha256[32]) {
    std::string sourceDir;
    if (env != nullptr && context != nullptr) {
        sourceDir = GetSourceDirFromJni(env, context);
    }
    if (sourceDir.empty()) {
        sourceDir = GetSourceDirFromMaps();
    }
    if (sourceDir.empty()) {
        return false;
    }
    return ReadSigningBlockSha256FromFile(sourceDir, outSha256);
}

bool VerifyApkV2V3ContentDigest(JNIEnv *env, jobject context) {
    std::string sourceDir;
    if (env != nullptr && context != nullptr) sourceDir = GetSourceDirFromJni(env, context);
    if (sourceDir.empty()) sourceDir = GetSourceDirFromMaps();
    return !sourceDir.empty() && VerifyContentDigestFromFile(env, sourceDir);
}
