// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <time.h>

#include <iomanip>
#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef FS_IOC_ENABLE_VERITY
#define FS_IOC_ENABLE_VERITY 1082156677
#endif

#ifndef FS_IOC_MEASURE_VERITY
#define FS_IOC_MEASURE_VERITY 3221513862
#endif

#ifndef FS_VERITY_FL
#define FS_VERITY_FL 1048576
#endif

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS 2148034049
#endif

struct fsverity_digest {
  __u16 digest_algorithm;
  __u16 digest_size; /* input/output */
  __u8 digest[];
};

constexpr int kMaxDigestSize = 64;
constexpr int kDefaultDigestSize = 32;
constexpr char kContents[] = "foobarbaz";

class MmapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Verity is implemented in VFS2.
    SKIP_IF(IsRunningWithVFS1());

    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    // Mount a tmpfs file system, to be wrapped by a verity fs.
    tmpfs_dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", tmpfs_dir_.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());

    // Create a new file in the tmpfs mount.
    file_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateFileWith(tmpfs_dir_.path(), kContents, 0777));
    filename_ = Basename(file_.path());
  }

  TempPath tmpfs_dir_;
  TempPath file_;
  std::string filename_;
};

// Provide a function to convert bytes to hex string, since
// absl::BytesToHexString does not seem to be compatible with golang
// hex.DecodeString used in verity due to zero-padding.
std::string BytesToHexString(uint8_t bytes[], int size) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < size; ++i) {
    ss << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

// Flip a random bit in the file represented by fd.
PosixError FlipRandomBit(int fd, int size) {
  // Generate a random offset in the file.
  srand(time(nullptr));
  unsigned int seed = 0;
  int random_offset = rand_r(&seed) % size;

  // Read a random byte and flip a bit in it.
  char buf[1];
  RETURN_ERROR_IF_SYSCALL_FAIL(PreadFd(fd, buf, 1, random_offset));
  buf[0] ^= 1;
  RETURN_ERROR_IF_SYSCALL_FAIL(PwriteFd(fd, buf, 1, random_offset));
  return NoError();
}

// Mount a verity on the tmpfs and enable both the file and the direcotry. Then
// mount a new verity with measured root hash.
PosixErrorOr<std::string> MountVerity(std::string tmpfs_dir,
                                      std::string filename) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir;
  ASSIGN_OR_RETURN_ERRNO(TempPath verity_dir, TempPath::CreateDir());
  RETURN_ERROR_IF_SYSCALL_FAIL(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()));

  // Enable both the file and the directory.
  ASSIGN_OR_RETURN_ERRNO(
      auto fd, Open(JoinPath(verity_dir.path(), filename), O_RDONLY, 0777));
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(fd.get(), FS_IOC_ENABLE_VERITY));
  ASSIGN_OR_RETURN_ERRNO(auto dir_fd, Open(verity_dir.path(), O_RDONLY, 0777));
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(dir_fd.get(), FS_IOC_ENABLE_VERITY));

  // Measure the root hash.
  uint8_t digest_array[sizeof(struct fsverity_digest) + kMaxDigestSize] = {0};
  struct fsverity_digest* digest =
      reinterpret_cast<struct fsverity_digest*>(digest_array);
  digest->digest_size = kMaxDigestSize;
  RETURN_ERROR_IF_SYSCALL_FAIL(
      ioctl(dir_fd.get(), FS_IOC_MEASURE_VERITY, digest));

  // Mount a verity fs with specified root hash.
  mount_opts +=
      ",root_hash=" + BytesToHexString(digest->digest, digest->digest_size);
  ASSIGN_OR_RETURN_ERRNO(TempPath verity_with_hash_dir, TempPath::CreateDir());
  RETURN_ERROR_IF_SYSCALL_FAIL(mount("", verity_with_hash_dir.path().c_str(),
                                     "verity", 0, mount_opts.c_str()));
  // Verity directories should not be deleted. Release the TempPath objects to
  // prevent those directories from being deleted by the destructor.
  verity_dir.release();
  return verity_with_hash_dir.release();
}

TEST_F(MmapTest, Mmap) {
  std::string verity_dir =
      ASSERT_NO_ERRNO_AND_VALUE(MountVerity(tmpfs_dir_.path(), filename_));

  // Make sure the file can be open and mmapped in the mounted verity fs.
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));

  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, sizeof(kContents) - 1, PROT_READ,
                                     MAP_SHARED, verity_fd.get(), 0));
  EXPECT_THAT(m.view(), ::testing::StrEq(kContents));
}

TEST_F(MmapTest, Modified) {
  std::string verity_dir =
      ASSERT_NO_ERRNO_AND_VALUE(MountVerity(tmpfs_dir_.path(), filename_));

  // Modify the file and check verification failure upon mmapping.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(tmpfs_dir_.path(), filename_), O_RDWR, 0777));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), sizeof(kContents) - 1));

  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, sizeof(kContents) - 1, PROT_READ,
                                     MAP_SHARED, verity_fd.get(), 0));

  // Memory fault is expected when Translate fails.
  EXPECT_EXIT(std::string(m.view()), ::testing::KilledBySignal(SIGSEGV), ".*");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
