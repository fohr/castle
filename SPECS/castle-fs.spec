%define   kmodtool sh /usr/lib/rpm/redhat/kmodtool

# hardcode for now:
%{!?kversion: %{expand: %%define kversion %(uname -r)}}

%define kmod_name castle
%define kverrel %(%{kmodtool} verrel %{?kversion} 2>/dev/null)
%define kvariants ""
%define kerneldir %{_usrsrc}/kernels/%{kverrel}-%{_target_cpu}

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

%define dkms_version %{buildver}.%{buildrev}

%description

%package -n %{kmod_name}-kmod
Summary:    Acunu kernel filesystem module
Group:      System Environment/Kernel

Provides:       %{name}-%{changesetver}

%description -n %{kmod_name}-kmod
kmod package for the Acunu kernel filesystem module

# magic hidden here:
# NOTE: these two extra defines will not be necessary in future.
%define kmp_version %{version}
%define kmp_release %{release}
%{expand:%(%{kmodtool} rpmtemplate_kmp %{kmod_name} %{kverrel} %{kvariants} 2>/dev/null)}

%package -n dkms-castle-fs
Summary:        DKMS-ready kernel source for castlefs
Group:          Development/Kernel
Provides:       openafs-kernel = %{PACKAGE_VERSION}
Requires(pre):  dkms
Requires(post): dkms
Requires:	castle-fs-kmod-common = %{version}

Provides:       %{name}-%{changesetver}

%description -n dkms-castle-fs
This package provides the DKMS-ready source code for the castle-fs kernel module.

%prep
%setup -q -n "castle-fs"

%build
make -C user/utils
make -C kernel KVER=%{kversion} KERNEL_DIR=%{kerneldir}

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/etc/udev/rules.d/
mkdir -p %{buildroot}/etc/castle-fs
mkdir -p %{buildroot}/opt/acunu/castle-fs/bin
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}%{_prefix}/src/castle-fs-%{dkms_version}
cp user/udev/castle-fs.rules %{buildroot}/etc/udev/rules.d/
cp user/udev/udev-watch %{buildroot}/etc/castle-fs/
cp user/utils/tests/CONFIG %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/tests/utils %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-init.sh %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-fini.sh %{buildroot}/opt/acunu/castle-fs/bin/
cp user/utils/castle-fs-cli %{buildroot}/usr/sbin/
cp kernel/*.c kernel/*.h kernel/Makefile %{buildroot}%{_prefix}/src/castle-fs-%{dkms_version}/

cat > %{buildroot}%{_prefix}/src/%{name}-%{dkms_version}/dkms.conf <<EOF

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

export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
make -C "%{kerneldir}" modules_install M=`pwd`/kernel

%clean
rm -rf %{buildroot}

%post -n dkms-castle-fs
dkms add -m castle-fs -v %{dkms_version} --rpm_safe_upgrade
if [ -z "$INHIBIT_DKMS_BUILD" ]
then
    dkms build -m castle-fs -v %{dkms_version} --rpm_safe_upgrade
    dkms install -m castle-fs -v %{dkms_version} --rpm_safe_upgrade
fi

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
