%define   kmodtool sh /usr/lib/rpm/redhat/kmodtool

# hardcode for now:
%{!?kversion: %{expand: %%define kversion %(uname -r)}}

%define kmod_name castle
%define kverrel %(%{kmodtool} verrel %{?kversion} 2>/dev/null)
%define kvariants ""
%define kerneldir %{_usrsrc}/kernels/%{kverrel}-%{_target_cpu}
%define krel	%(echo %{kverrel} | sed -e 's/-/_/g')

%define groupname castle

Name:           castle-fs
Version:        %{buildver}
Release:        %{buildrev}
Summary:        Acunu kernel filesystem

Group:          Filesystem
License:        Closed
URL:            http://www.acunu.com/
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides: castle-fs-kmod-common = %{version}
Provides:       %{name}-%{changesetver}

Requires(pre): shadow-utils
Requires: castle-cli

%description

# magic hidden here:
# NOTE: these two extra defines will not be necessary in future.
%define kmp_version %{version}
%define kmp_release %{buildrev}_%{krel}
# kmodtool is a bit brainless in how it handles kmp_release
%{expand:%(kmp_version=foo kmp_release=bar %{kmodtool} rpmtemplate_kmp %{kmod_name} %{kverrel} %{kvariants} 2>/dev/null)}

%prep
%setup -q -n "castle-fs"

%build
make -C user/utils
make -C kernel KVER=%{kversion} KERNEL_DIR=%{kerneldir} DEBUG=n PERF_DEBUG=n

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/etc/udev/rules.d/
mkdir -p %{buildroot}/etc/castle-fs
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/share/castle-fs
cp user/udev/castle-fs.rules %{buildroot}/etc/udev/rules.d/
cp user/udev/udev-watch %{buildroot}/etc/castle-fs/
cp user/utils/init-utils %{buildroot}/usr/share/castle-fs/
cp user/utils/castle-fs-init.sh %{buildroot}/usr/share/castle-fs/
cp user/utils/castle-fs-fini.sh %{buildroot}/usr/share/castle-fs/
cp user/utils/castle-scan %{buildroot}/usr/sbin/
cp user/utils/castle_probe_device %{buildroot}/usr/sbin/castle-probe-device

export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
make -C "%{kerneldir}" modules_install M=`pwd`/kernel

%clean
rm -rf %{buildroot}

%pre
getent group %{groupname} >/dev/null || groupadd -r %{groupname}

%files
%defattr(-,root,root,-)
/etc/udev/rules.d
/etc/castle-fs/udev-watch
/usr/sbin/castle-scan
/usr/sbin/castle-probe-device
/usr/share/castle-fs

%changelog
* Thu Sep  9 2010 Andrew Suffield <asuffield@acunu.com> - %{buildver}-%{buildrev}
- Initial package
