// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#include "reallyme_zk_platform_abi.h"

#include <jni.h>
#include <stdint.h>
#include <string.h>

#include <limits>
#include <new>
#include <vector>

namespace {

constexpr uint32_t kReallyMeZkPlatformStatusOk = 0;
constexpr uint32_t kReallyMeZkPlatformStatusNullArgument = 1;
constexpr uint32_t kReallyMeZkPlatformStatusInternalFailure = 5;
constexpr uint32_t kReallyMeZkPlatformStatusInvalidContext = 7;
constexpr uint32_t kReallyMeZkPlatformStatusInvalidMode = 8;
constexpr uint32_t kReallyMeZkErrorReasonArtifactMismatch = 10;
constexpr uint32_t kReallyMeZkErrorReasonBackendFailure = 12;
constexpr uint32_t kReallyMeZkErrorReasonMalformedProtobuf = 21;
constexpr jsize kReallyMeMaxNativeOutputBytes = 4 * 1024 * 1024;
constexpr jsize kReallyMeMaxProviderOperationBytes =
    (256 * 1024 * 4) + (4 * 1024 * 1024 * 4) + (3 * 1024 * 1024);
constexpr jsize kReallyMeMaxPlatformPathBytes = 4096;
constexpr jsize kReallyMeMaxReleaseIndexBytes = 1024 * 1024;
constexpr jsize kReallyMeDigestSha256Bytes = 32;
constexpr jsize kReallyMeVerifierCrsG1Bytes = 64;
constexpr jsize kReallyMeVerifierCrsG2Bytes = 128;
constexpr jsize kReallyMeFullProverCrsG1Bytes = 67'108'928;
constexpr jsize kReallyMeContextInputCount = 5;
constexpr jsize kReallyMeContextInputArtifactRoot = 0;
constexpr jsize kReallyMeContextInputReleaseIndex = 1;
constexpr jsize kReallyMeContextInputReleaseIndexSha256 = 2;
constexpr jsize kReallyMeContextInputCrsG1 = 3;
constexpr jsize kReallyMeContextInputCrsG2 = 4;
constexpr jint kReallyMeCrsModeVerifierOnly = 1;
constexpr jint kReallyMeCrsModeFullProver = 2;

void wipe_bytes(uint8_t *ptr, size_t len) noexcept {
  if (ptr == nullptr) {
    return;
  }
  volatile uint8_t *cursor = ptr;
  for (size_t index = 0; index < len; ++index) {
    cursor[index] = 0;
  }
}

struct WipingBytes {
  std::vector<uint8_t> bytes;

  WipingBytes() = default;
  WipingBytes(const WipingBytes &) = delete;
  WipingBytes &operator=(const WipingBytes &) = delete;

  ~WipingBytes() noexcept {
    wipe_bytes(bytes.data(), bytes.size());
  }
};

jlong checked_u32(uint32_t value) noexcept {
  return static_cast<jlong>(value);
}

jlongArray make_status(JNIEnv *env, uint32_t status_code, uint32_t reason_code) {
  jlong fields[2] = {
      checked_u32(status_code),
      checked_u32(reason_code),
  };
  jlongArray result = env->NewLongArray(2);
  if (result == nullptr) {
    return nullptr;
  }
  env->SetLongArrayRegion(result, 0, 2, fields);
  return result;
}

jlongArray make_context_result(JNIEnv *env,
                               uint32_t status_code,
                               uint32_t reason_code,
                               reallyme_zk_platform_context_t *context) {
  jlong handle = 0;
  static_assert(sizeof(jlong) >= sizeof(uintptr_t),
                "JNI handle must carry a native pointer");
  if (context != nullptr) {
    handle = static_cast<jlong>(reinterpret_cast<uintptr_t>(context));
  }
  jlong fields[3] = {
      checked_u32(status_code),
      checked_u32(reason_code),
      handle,
  };
  jlongArray result = env->NewLongArray(3);
  if (result == nullptr) {
    if (context != nullptr) {
      reallyme_zk_platform_context_destroy(context);
    }
    return nullptr;
  }
  env->SetLongArrayRegion(result, 0, 3, fields);
  return result;
}

bool copy_byte_array(JNIEnv *env,
                     jbyteArray input,
                     jsize minimum_len,
                     jsize maximum_len,
                     WipingBytes *output) {
  if (input == nullptr || output == nullptr) {
    return false;
  }
  const jsize len = env->GetArrayLength(input);
  if (len < minimum_len || len > maximum_len) {
    return false;
  }
  output->bytes.resize(static_cast<size_t>(len));
  env->GetByteArrayRegion(input,
                          0,
                          len,
                          reinterpret_cast<jbyte *>(output->bytes.data()));
  if (env->ExceptionCheck() == JNI_TRUE) {
    wipe_bytes(output->bytes.data(), output->bytes.size());
    output->bytes.clear();
    return false;
  }
  return true;
}

bool copy_byte_array_from_object_array(JNIEnv *env,
                                       jobjectArray inputs,
                                       jsize index,
                                       jsize minimum_len,
                                       jsize maximum_len,
                                       WipingBytes *output) {
  if (inputs == nullptr || output == nullptr) {
    return false;
  }
  jobject element = env->GetObjectArrayElement(inputs, index);
  if (env->ExceptionCheck() == JNI_TRUE || element == nullptr) {
    return false;
  }
  jbyteArray bytes = reinterpret_cast<jbyteArray>(element);
  const bool copied =
      copy_byte_array(env, bytes, minimum_len, maximum_len, output);
  env->DeleteLocalRef(element);
  return copied;
}

jobject make_dispatch_result(JNIEnv *env,
                             uint32_t status_code,
                             uint32_t reason_code,
                             jbyteArray output) {
  jclass result_class = env->FindClass("me/really/zk/ZkNativeDispatchResult");
  if (result_class == nullptr) {
    return nullptr;
  }
  jmethodID constructor = env->GetMethodID(result_class, "<init>", "(II[B)V");
  if (constructor == nullptr) {
    return nullptr;
  }
  return env->NewObject(result_class,
                        constructor,
                        static_cast<jint>(status_code),
                        static_cast<jint>(reason_code),
                        output);
}

jbyteArray empty_byte_array(JNIEnv *env) {
  return env->NewByteArray(0);
}

jobject make_failure_dispatch_result(JNIEnv *env,
                                     uint32_t status_code,
                                     uint32_t reason_code) {
  jbyteArray output = empty_byte_array(env);
  if (output == nullptr) {
    return nullptr;
  }
  return make_dispatch_result(env, status_code, reason_code, output);
}

jbyteArray copy_output(JNIEnv *env, reallyme_zk_platform_buffer_t buffer) {
  if (buffer.ptr == nullptr || buffer.len == 0 ||
      buffer.len > static_cast<size_t>(kReallyMeMaxNativeOutputBytes) ||
      buffer.len > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
    return nullptr;
  }
  jbyteArray output = env->NewByteArray(static_cast<jsize>(buffer.len));
  if (output == nullptr) {
    return nullptr;
  }
  env->SetByteArrayRegion(output,
                          0,
                          static_cast<jsize>(buffer.len),
                          reinterpret_cast<const jbyte *>(buffer.ptr));
  if (env->ExceptionCheck() == JNI_TRUE) {
    return nullptr;
  }
  return output;
}

reallyme_zk_platform_context_t *context_from_handle(jlong handle) noexcept {
  if (handle == 0) {
    return nullptr;
  }
  return reinterpret_cast<reallyme_zk_platform_context_t *>(
      static_cast<uintptr_t>(handle));
}

}  // namespace

extern "C" JNIEXPORT jlongArray JNICALL
Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreate(
    JNIEnv *env,
    jobject,
    jobjectArray inputs,
    jint crs_mode_code) {
  try {
    jsize expected_crs_g1_len = 0;
    if (crs_mode_code == kReallyMeCrsModeVerifierOnly) {
      expected_crs_g1_len = kReallyMeVerifierCrsG1Bytes;
    } else if (crs_mode_code == kReallyMeCrsModeFullProver) {
      expected_crs_g1_len = kReallyMeFullProverCrsG1Bytes;
    } else {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusInvalidMode,
                                 kReallyMeZkErrorReasonArtifactMismatch,
                                 nullptr);
    }
    if (inputs == nullptr ||
        env->GetArrayLength(inputs) != kReallyMeContextInputCount) {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusNullArgument,
                                 kReallyMeZkErrorReasonMalformedProtobuf,
                                 nullptr);
    }
    WipingBytes artifact_root_bytes;
    WipingBytes release_index_bytes;
    WipingBytes release_index_sha256_bytes;
    WipingBytes crs_g1_bytes;
    WipingBytes crs_g2_bytes;
    if (!copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputArtifactRoot,
                                           1,
                                           kReallyMeMaxPlatformPathBytes,
                                           &artifact_root_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputReleaseIndex,
                                           1,
                                           kReallyMeMaxReleaseIndexBytes,
                                           &release_index_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputReleaseIndexSha256,
                                           kReallyMeDigestSha256Bytes,
                                           kReallyMeDigestSha256Bytes,
                                           &release_index_sha256_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputCrsG1,
                                           expected_crs_g1_len,
                                           expected_crs_g1_len,
                                           &crs_g1_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputCrsG2,
                                           kReallyMeVerifierCrsG2Bytes,
                                           kReallyMeVerifierCrsG2Bytes,
                                           &crs_g2_bytes)) {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusNullArgument,
                                 kReallyMeZkErrorReasonMalformedProtobuf,
                                 nullptr);
    }

    reallyme_zk_platform_context_result_t result =
        reallyme_zk_platform_context_create(
            artifact_root_bytes.bytes.data(),
            artifact_root_bytes.bytes.size(),
            release_index_bytes.bytes.data(),
            release_index_bytes.bytes.size(),
            release_index_sha256_bytes.bytes.data(),
            release_index_sha256_bytes.bytes.size(),
            crs_g1_bytes.bytes.data(),
            crs_g1_bytes.bytes.size(),
            crs_g2_bytes.bytes.data(),
            crs_g2_bytes.bytes.size(),
            static_cast<uint32_t>(crs_mode_code));

    return make_context_result(env,
                               result.status_code,
                               result.error_reason_code,
                               result.context);
  } catch (...) {
    if (env->ExceptionCheck() == JNI_TRUE) {
      env->ExceptionClear();
    }
    return make_context_result(env,
                               kReallyMeZkPlatformStatusInternalFailure,
                               kReallyMeZkErrorReasonBackendFailure,
                               nullptr);
  }
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextCreateWithCrsFiles(
    JNIEnv *env,
    jobject,
    jobjectArray inputs,
    jint crs_mode_code) {
  try {
    if (crs_mode_code != kReallyMeCrsModeVerifierOnly &&
        crs_mode_code != kReallyMeCrsModeFullProver) {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusInvalidMode,
                                 kReallyMeZkErrorReasonArtifactMismatch,
                                 nullptr);
    }
    if (inputs == nullptr ||
        env->GetArrayLength(inputs) != kReallyMeContextInputCount) {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusNullArgument,
                                 kReallyMeZkErrorReasonMalformedProtobuf,
                                 nullptr);
    }
    WipingBytes artifact_root_bytes;
    WipingBytes release_index_bytes;
    WipingBytes release_index_sha256_bytes;
    WipingBytes crs_g1_path_bytes;
    WipingBytes crs_g2_path_bytes;
    if (!copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputArtifactRoot,
                                           1,
                                           kReallyMeMaxPlatformPathBytes,
                                           &artifact_root_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputReleaseIndex,
                                           1,
                                           kReallyMeMaxReleaseIndexBytes,
                                           &release_index_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputReleaseIndexSha256,
                                           kReallyMeDigestSha256Bytes,
                                           kReallyMeDigestSha256Bytes,
                                           &release_index_sha256_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputCrsG1,
                                           1,
                                           kReallyMeMaxPlatformPathBytes,
                                           &crs_g1_path_bytes) ||
        !copy_byte_array_from_object_array(env,
                                           inputs,
                                           kReallyMeContextInputCrsG2,
                                           1,
                                           kReallyMeMaxPlatformPathBytes,
                                           &crs_g2_path_bytes)) {
      return make_context_result(env,
                                 kReallyMeZkPlatformStatusNullArgument,
                                 kReallyMeZkErrorReasonMalformedProtobuf,
                                 nullptr);
    }

    reallyme_zk_platform_context_result_t result =
        reallyme_zk_platform_context_create_with_crs_files(
            artifact_root_bytes.bytes.data(),
            artifact_root_bytes.bytes.size(),
            release_index_bytes.bytes.data(),
            release_index_bytes.bytes.size(),
            release_index_sha256_bytes.bytes.data(),
            release_index_sha256_bytes.bytes.size(),
            crs_g1_path_bytes.bytes.data(),
            crs_g1_path_bytes.bytes.size(),
            crs_g2_path_bytes.bytes.data(),
            crs_g2_path_bytes.bytes.size(),
            static_cast<uint32_t>(crs_mode_code));

    return make_context_result(env,
                               result.status_code,
                               result.error_reason_code,
                               result.context);
  } catch (...) {
    if (env->ExceptionCheck() == JNI_TRUE) {
      env->ExceptionClear();
    }
    return make_context_result(env,
                               kReallyMeZkPlatformStatusInternalFailure,
                               kReallyMeZkErrorReasonBackendFailure,
                               nullptr);
  }
}

extern "C" JNIEXPORT jobject JNICALL
Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeDispatch(
    JNIEnv *env,
    jobject,
    jlong context_handle,
    jbyteArray request) {
  try {
    reallyme_zk_platform_context_t *context = context_from_handle(context_handle);
    if (context == nullptr) {
      return make_failure_dispatch_result(env,
                                          kReallyMeZkPlatformStatusInvalidContext,
                                          kReallyMeZkErrorReasonBackendFailure);
    }

    WipingBytes request_bytes;
    if (!copy_byte_array(
            env, request, 1, kReallyMeMaxProviderOperationBytes, &request_bytes)) {
      return make_failure_dispatch_result(env,
                                          kReallyMeZkPlatformStatusNullArgument,
                                          kReallyMeZkErrorReasonMalformedProtobuf);
    }

    reallyme_zk_platform_result_t result =
        reallyme_zk_platform_dispatch(context,
                                      request_bytes.bytes.data(),
                                      request_bytes.bytes.size());

    if (result.status_code != kReallyMeZkPlatformStatusOk) {
      return make_failure_dispatch_result(env,
                                          result.status_code,
                                          result.error_reason_code);
    }
    jbyteArray output = copy_output(env, result.output);
    reallyme_zk_platform_status_t destroy_status =
        reallyme_zk_platform_buffer_destroy(result.output);
    if (output == nullptr ||
        destroy_status.status_code != kReallyMeZkPlatformStatusOk) {
      if (env->ExceptionCheck() == JNI_TRUE) {
        env->ExceptionClear();
      }
      return make_failure_dispatch_result(env,
                                          kReallyMeZkPlatformStatusInternalFailure,
                                          kReallyMeZkErrorReasonBackendFailure);
    }
    return make_dispatch_result(env,
                                result.status_code,
                                result.error_reason_code,
                                output);
  } catch (...) {
    if (env->ExceptionCheck() == JNI_TRUE) {
      env->ExceptionClear();
    }
    return make_failure_dispatch_result(env,
                                        kReallyMeZkPlatformStatusInternalFailure,
                                        kReallyMeZkErrorReasonBackendFailure);
  }
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_me_really_zk_JniReallyMeZkPlatformNativeBridge_nativeContextDestroy(
    JNIEnv *env,
    jobject,
    jlong context_handle) {
  try {
    reallyme_zk_platform_context_t *context = context_from_handle(context_handle);
    reallyme_zk_platform_status_t status =
        reallyme_zk_platform_context_destroy(context);
    return make_status(env, status.status_code, status.error_reason_code);
  } catch (...) {
    if (env->ExceptionCheck() == JNI_TRUE) {
      env->ExceptionClear();
    }
    return make_status(env,
                       kReallyMeZkPlatformStatusInternalFailure,
                       kReallyMeZkErrorReasonBackendFailure);
  }
}
