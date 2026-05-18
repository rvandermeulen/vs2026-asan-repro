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
  // Mirror Chromium's iterator-range ctor:
  //   Sid::Sid(const void* sid, size_t length)
  //     : sid_(static_cast<const char*>(sid),
  //            static_cast<const char*>(sid) + length) {}
  Sid(const void* sid, size_t length)
      : sid_(static_cast<const char*>(sid),
             static_cast<const char*>(sid) + length) {}
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

// Mirror of base::win::AccessControlList: only holds the ACL buffer.
class AccessControlList {
 public:
  AccessControlList() = default;
  explicit AccessControlList(std::unique_ptr<uint8_t[]> acl)
      : acl_(std::move(acl)) {}
  AccessControlList(const AccessControlList&) = delete;
  AccessControlList(AccessControlList&&) noexcept = default;
  AccessControlList& operator=(const AccessControlList&) = delete;
  AccessControlList& operator=(AccessControlList&&) noexcept = default;

  void* get() const { return acl_.get(); }

 private:
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

  bool dacl_protected() const { return dacl_protected_; }
  bool sacl_protected() const { return sacl_protected_; }

  const std::optional<Sid>& owner() const { return owner_; }
  const std::optional<Sid>& group() const { return group_; }
  const std::optional<AccessControlList>& dacl() const { return dacl_; }
  const std::optional<AccessControlList>& sacl() const { return sacl_; }

  bool WriteToHandle(HANDLE object, SE_OBJECT_TYPE type,
                     SECURITY_INFORMATION info) const;

 private:
  std::optional<Sid> owner_;
  std::optional<Sid> group_;
  std::optional<AccessControlList> dacl_;
  std::optional<AccessControlList> sacl_;
  bool dacl_protected_ = false;
  bool sacl_protected_ = false;
};

// Mirror Chromium's anonymous-namespace template + UnwrapSid/UnwrapAcl helpers.
namespace {

PSID UnwrapSid(const std::optional<Sid>& sid) {
  if (!sid) return nullptr;
  return const_cast<PSID>(sid->GetPSID());
}

PACL UnwrapAcl(const std::optional<AccessControlList>& acl) {
  if (!acl) return nullptr;
  return reinterpret_cast<PACL>(acl->get());
}

template <typename T>
bool SetSecurityDescriptor(const SecurityDescriptor& sd,
                           T object,
                           SE_OBJECT_TYPE object_type,
                           SECURITY_INFORMATION security_info,
                           DWORD(WINAPI* set_sd)(T,
                                                 SE_OBJECT_TYPE,
                                                 SECURITY_INFORMATION,
                                                 PSID,
                                                 PSID,
                                                 PACL,
                                                 PACL)) {
  security_info &= ~(PROTECTED_DACL_SECURITY_INFORMATION |
                     UNPROTECTED_DACL_SECURITY_INFORMATION |
                     PROTECTED_SACL_SECURITY_INFORMATION |
                     UNPROTECTED_SACL_SECURITY_INFORMATION);
  if (security_info & DACL_SECURITY_INFORMATION) {
    if (sd.dacl_protected()) {
      security_info |= PROTECTED_DACL_SECURITY_INFORMATION;
    } else {
      security_info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
    }
  }
  if (security_info & SACL_SECURITY_INFORMATION) {
    if (sd.sacl_protected()) {
      security_info |= PROTECTED_SACL_SECURITY_INFORMATION;
    } else {
      security_info |= UNPROTECTED_SACL_SECURITY_INFORMATION;
    }
  }
  DWORD error = set_sd(object, object_type, security_info,
                       UnwrapSid(sd.owner()), UnwrapSid(sd.group()),
                       UnwrapAcl(sd.dacl()), UnwrapAcl(sd.sacl()));
  return error == ERROR_SUCCESS;
}

}  // namespace

bool SecurityDescriptor::WriteToHandle(HANDLE handle,
                                       SE_OBJECT_TYPE type,
                                       SECURITY_INFORMATION info) const {
  bool ok = SetSecurityDescriptor<HANDLE>(*this, handle, type, info,
                                          ::SetSecurityInfo);
  std::printf("WriteToHandle ok=%d\n", ok);
  return ok;
}

// Helper: clone a PSID into a Sid. Mirrors Chromium's Sid::FromPSID.
static Sid CloneSid(PSID psid) {
  if (!psid) {
    return Sid();
  }
  return Sid(psid, ::GetLengthSid(psid));
}

// Helper: clone a PACL into an AccessControlList. Mirrors Chromium's
// AclToBuffer() in security/sandbox/chromium/base/win/access_control_list.cc.
static AccessControlList CloneAcl(const ACL* acl) {
  if (!acl) {
    return AccessControlList(nullptr);
  }
  size_t size = acl->AclSize;
  auto bytes = std::make_unique<uint8_t[]>(size);
  std::memcpy(bytes.get(), acl, size);
  return AccessControlList(std::move(bytes));
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
    sd.set_dacl(CloneAcl(dacl_pacl));
  }
  if (info & (LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)) {
    sd.set_sacl(CloneAcl(sacl_pacl));
  }

  ::LocalFree(raw_sd);
  return sd;
}

// Mirror of sandbox::HardenTokenIntegrityLevelPolicy in
// security/sandbox/chromium/sandbox/win/src/restricted_token_utils.cc.
// This is the exact function whose stack frame contains the use-after-poisoned
// 'sd' in the Firefox CI failure.
DWORD HardenTokenIntegrityLevelPolicy(HANDLE token) {
  std::optional<SecurityDescriptor> sd =
      FromHandle(token, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION);
  if (!sd) {
    return ::GetLastError();
  }

  // If no SACL then nothing to do.
  if (!sd->sacl()) {
    return ERROR_SUCCESS;
  }
  PACL sacl = reinterpret_cast<PACL>(sd->sacl()->get());

  for (DWORD ace_index = 0; ace_index < sacl->AceCount; ++ace_index) {
    PSYSTEM_MANDATORY_LABEL_ACE ace;
    if (::GetAce(sacl, ace_index, reinterpret_cast<LPVOID*>(&ace)) &&
        ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
      ace->Mask |= SYSTEM_MANDATORY_LABEL_NO_READ_UP |
                   SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
      break;
    }
  }
  if (!sd->WriteToHandle(token, SE_KERNEL_OBJECT,
                         LABEL_SECURITY_INFORMATION)) {
    return ::GetLastError();
  }
  return ERROR_SUCCESS;
}

int main() {
  HANDLE token = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
    std::fprintf(stderr, "OpenProcessToken failed: %lu\n", ::GetLastError());
    return 1;
  }
  DWORD result = HardenTokenIntegrityLevelPolicy(token);
  ::CloseHandle(token);
  std::printf("HardenTokenIntegrityLevelPolicy result=%lu\n", result);
  return 0;
}
