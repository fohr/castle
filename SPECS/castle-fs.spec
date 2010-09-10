Name:           castle-fs
Version:        %{buildver}
Release:        %{buildrev}
Summary:        Acunu Kernel Filesystem

Group:          Filesystem
License:        Closed
URL:            http://www.acunu.com/
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides: castle-fs-kmod-common = %{version}

%define dkms_version %{buildver}.%{buildrev}

%description

%package -n dkms-castle-fs
Summary:        DKMS-ready kernel source for castlefs
Group:          Development/Kernel
Provides:       openafs-kernel = %{PACKAGE_VERSION}
Requires(pre):  dkms
Requires(post): dkms
Requires:	castle-fs-kmod-common = %{version}

%description -n dkms-castle-fs
This package provides the DKMS-ready source code for the castle-fs kernel module.

%prep
%setup -q -n "castle-fs"

%build
make -C user/utils
make -C kernel castle_compile.h

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/etc/udev/rules.d/
mkdir -p %{buildroot}/etc/castle-fs
mkdir -p %{buildroot}/opt/acunu/castle-fs/bin
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}%{_prefix}/src
cp user/udev/castle-fs.rules %{buildroot}/etc/udev/rules.d/
cp user/udev/udev-watch %{buildroot}/etc/castle-fs/
cp user/utils/tests/CONFIG %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/tests/utils %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-init.sh %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-fini.sh %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-cli %{buildroot}/usr/sbin/
cp -r kernel %{buildroot}%{_prefix}/src/castle-fs-%{dkms_version}

cat > $RPM_BUILD_ROOT%{_prefix}/src/%{name}-%{dkms_version}/dkms.conf <<EOF

PACKAGE_VERSION="%{dkms_version}"

# Items below here should not have to change with each driver version
PACKAGE_NAME="castle-fs"
MAKE[0]="make KERNEL_DIR=\${kernel_source_dir}"
CLEAN="make clean"

BUILT_MODULE_NAME[0]="\$PACKAGE_NAME"
DEST_MODULE_LOCATION[0]="/extra"
STRIP[0]=no
AUTOINSTALL=yes

EOF

%clean
rm -rf %{buildroot}

%post -n dkms-castle-fs
dkms add -m castle-fs -v %{dkms_version} --rpm_safe_upgrade
dkms build -m castle-fs -v %{dkms_version} --rpm_safe_upgrade
dkms install -m castle-fs -v %{dkms_version} --rpm_safe_upgrade

%preun -n dkms-castle-fs
dkms remove -m castle-fs -v %{dkms_version} --rpm_safe_upgrade --all ||:

%files
%defattr(-,root,root,-)
/etc/udev/rules.d
/etc/castle-fs/udev-watch
/opt/acunu
/usr/sbin/castle-fs-cli

%files -n dkms-castle-fs
%defattr(-,root,root)
%{_prefix}/src/castle-fs-%{dkms_version}

%changelog
* Thu Sep  9 2010 Andrew Suffield <asuffield@acunu.com> - %{buildver}-%{buildrev}
- Initial package
