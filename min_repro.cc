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

#include <cstdint>
#include <cstdio>
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

// Mirror of SecurityDescriptor::FromHandle: returns by value via optional,
// with all four members populated to mimic what FromHandle returns for a real
// token security descriptor.
static std::optional<SecurityDescriptor> FromHandle() {
  SecurityDescriptor sd;
  sd.set_owner(Sid(std::vector<char>(12, 0x01)));
  sd.set_group(Sid(std::vector<char>(12, 0x02)));
  {
    auto acl_bytes = std::make_unique<uint8_t[]>(32);
    sd.set_dacl(AccessControlList(Sid(std::vector<char>(12, 0x03)),
                                  std::move(acl_bytes)));
  }
  {
    auto acl_bytes = std::make_unique<uint8_t[]>(32);
    sd.set_sacl(AccessControlList(Sid(std::vector<char>(12, 0x04)),
                                  std::move(acl_bytes)));
  }
  return sd;
}

int main() {
  std::optional<SecurityDescriptor> sd = FromHandle();
  if (!sd) {
    return 1;
  }
  sd->WriteToHandle();
  return 0;
}
