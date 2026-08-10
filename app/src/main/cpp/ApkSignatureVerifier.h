#ifndef ARK_APK_SIGNATURE_VERIFIER_H
#define ARK_APK_SIGNATURE_VERIFIER_H

#include <jni.h>
#include <cstdint>
#include <string>

// Reads the installed APK directly via raw Linux syscalls (__NR_openat, __NR_pread64),
// parses the v2 / v3 APK Signing Block, and extracts the 32-byte SHA-256 digest
// of the signing certificate. Returns true on success, false on failure.
bool ReadApkSigningBlockSha256(JNIEnv *env, jobject context, uint8_t outSha256[32]);

// Recomputes the SHA-256 APK content digest defined by APK Signature Scheme v2/v3
// and compares it with the digest embedded in signed data. This detects APK bytes
// modified while retaining an old signing block; callers must additionally verify
// the signer's cryptographic signature to establish signer authenticity.
bool VerifyApkV2V3ContentDigest(JNIEnv *env, jobject context);

#endif // ARK_APK_SIGNATURE_VERIFIER_H
