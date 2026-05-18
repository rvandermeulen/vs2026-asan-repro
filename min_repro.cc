// Minimal repro attempt for VS 2026 18.6 + clang-cl + ASan use-after-poison.
//
// Background: in Firefox's CI we see ASan use-after-poison ("Poisoned by user",
// shadow byte f7) inside the equivalent of base::win::SecurityDescriptor::
// WriteToHandle when called from sandbox::HardenTokenIntegrityLevelPolicy. The
// failing read is on stack memory holding an std::optional<SecurityDescriptor>.
//
// _DISABLE_VECTOR_ANNOTATION, _DISABLE_STRING_ANNOTATION,
// -fno-sanitize-address-use-after-scope, -mllvm -asan-stack=0, and
// -U_MSVC_STL_HARDENING all fail to suppress the crash, so the source of
// __asan_poison_memory_region calls is not yet identified.
//
// This file mirrors the shape of base::win::SecurityDescriptor's storage
// without doing any actual Windows security work. The goal is to see if just
// constructing and reading the optional<SecurityDescriptor> through the same
// pattern is enough to reproduce f7 poisoning.

#include <Windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <sddl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

// Mirror of base::win::Sid.
class Sid {
 public:
  Sid() = default;
  explicit Sid(std::vector<char> bytes) : sid_(std::move(bytes)) {}
  Sid(const Sid&) = default;
  Sid(Sid&&) noexcept = default;
  Sid& operator=(const Sid&) = default;
  Sid& operator=(Sid&&) noexcept = default;

  const void* GetPSID() const {
    return sid_.empty() ? nullptr : sid_.data();
  }

 private:
  std::vector<char> sid_;
};

// Mirror of base::win::AccessControlList.
class AccessControlList {
 public:
  AccessControlList() = default;
  AccessControlList(Sid sid, std::unique_ptr<uint8_t[]> acl)
      : sid_(std::move(sid)), acl_(std::move(acl)) {}
  AccessControlList(const AccessControlList&) = delete;
  AccessControlList(AccessControlList&&) noexcept = default;
  AccessControlList& operator=(const AccessControlList&) = delete;
  AccessControlList& operator=(AccessControlList&&) noexcept = default;

  void* get() const { return acl_.get(); }

 private:
  Sid sid_;
  std::unique_ptr<uint8_t[]> acl_;
};

// Mirror of base::win::SecurityDescriptor.
class SecurityDescriptor {
 public:
  SecurityDescriptor() = default;
  SecurityDescriptor(SecurityDescriptor&&) noexcept = default;

  void set_owner(Sid s) { owner_ = std::move(s); }
  void set_group(Sid s) { group_ = std::move(s); }
  void set_dacl(AccessControlList a) { dacl_ = std::move(a); }
  void set_sacl(AccessControlList a) { sacl_ = std::move(a); }

  // Mimic WriteToHandle: reads all four optional members. In Chromium this is
  // where the use-after-poison fires (security_descriptor.cc:166).
  bool WriteToHandle() const {
    const void* o = owner_ ? owner_->GetPSID() : nullptr;
    const void* g = group_ ? group_->GetPSID() : nullptr;
    void* d = dacl_ ? dacl_->get() : nullptr;
    void* s = sacl_ ? sacl_->get() : nullptr;
    std::printf("o=%p g=%p d=%p s=%p\n", o, g, d, s);
    return true;
  }

 private:
  std::optional<Sid> owner_;
  std::optional<Sid> group_;
  std::optional<AccessControlList> dacl_;
  std::optional<AccessControlList> sacl_;
  bool dacl_protected_ = false;
  bool sacl_protected_ = false;
};

// Helper: clone a PSID into a std::vector<char>.
static Sid CloneSid(PSID psid) {
  if (!psid) {
    return Sid();
  }
  DWORD len = ::GetLengthSid(psid);
  std::vector<char> bytes(len);
  ::CopySid(len, bytes.data(), psid);
  return Sid(std::move(bytes));
}

// Helper: clone a PACL plus its owner-SID into an AccessControlList.
static AccessControlList CloneAcl(PACL acl, PSID owner_sid) {
  Sid sid = CloneSid(owner_sid);
  if (!acl) {
    return AccessControlList(std::move(sid), nullptr);
  }
  ACL_SIZE_INFORMATION info{};
  ::GetAclInformation(acl, &info, sizeof(info), AclSizeInformation);
  auto bytes = std::make_unique<uint8_t[]>(info.AclBytesInUse);
  std::memcpy(bytes.get(), acl, info.AclBytesInUse);
  return AccessControlList(std::move(sid), std::move(bytes));
}

// Mirror of SecurityDescriptor::FromHandle. Calls the same Windows API
// (GetSecurityInfo) Chromium uses, parses the kernel-returned buffer into our
// minimal Sid / AccessControlList objects.
static std::optional<SecurityDescriptor> FromHandle(HANDLE object,
                                                    SE_OBJECT_TYPE type,
                                                    SECURITY_INFORMATION info) {
  PSID owner_psid = nullptr;
  PSID group_psid = nullptr;
  PACL dacl_pacl = nullptr;
  PACL sacl_pacl = nullptr;
  PSECURITY_DESCRIPTOR raw_sd = nullptr;
  DWORD err = ::GetSecurityInfo(object, type, info, &owner_psid, &group_psid,
                                &dacl_pacl, &sacl_pacl, &raw_sd);
  if (err != ERROR_SUCCESS) {
    std::fprintf(stderr, "GetSecurityInfo failed: %lu\n", err);
    return std::nullopt;
  }

  SecurityDescriptor sd;
  if (info & OWNER_SECURITY_INFORMATION) {
    sd.set_owner(CloneSid(owner_psid));
  }
  if (info & GROUP_SECURITY_INFORMATION) {
    sd.set_group(CloneSid(group_psid));
  }
  if (info & DACL_SECURITY_INFORMATION) {
    sd.set_dacl(CloneAcl(dacl_pacl, owner_psid));
  }
  if (info & (LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)) {
    sd.set_sacl(CloneAcl(sacl_pacl, owner_psid));
  }

  ::LocalFree(raw_sd);
  return sd;
}

int main() {
  // Mirror Chromium's HardenTokenIntegrityLevelPolicy: open the current
  // process token and read its label SACL.
  HANDLE token = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
    std::fprintf(stderr, "OpenProcessToken failed: %lu\n", ::GetLastError());
    return 1;
  }

  std::optional<SecurityDescriptor> sd =
      FromHandle(token, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION);
  ::CloseHandle(token);
  if (!sd) {
    return 1;
  }
  sd->WriteToHandle();
  return 0;
}
