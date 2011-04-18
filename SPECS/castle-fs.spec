%define   kmodtool sh /usr/lib/rpm/redhat/kmodtool

# hardcode for now:
%{!?kversion: %{expand: %%define kversion %(uname -r)}}

%define kmod_name castle
%define kverrel %(%{kmodtool} verrel %{?kversion} 2>/dev/null)
%define kvariants "" xen debug
%define krel	%(echo %{kverrel} | sed -e 's/-/_/g')
%define krel_nohg %(echo %{krel} | sed -e 's/\.hg.*$//')

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
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
Requires: castle-cli

BuildRequires: doxygen
BuildRequires: graphviz-gd

%description

# magic hidden here:
# NOTE: these two extra defines will not be necessary in future.
%define kmp_version %{version}
%define kmp_release %{buildrev}_%{krel_nohg}
# kmodtool is a bit brainless in how it handles kmp_release
%{expand:%(kmp_version=foo kmp_release=bar %{kmodtool} rpmtemplate_kmp %{kmod_name} %{kverrel} %{kvariants} 2>/dev/null)}

%prep
%setup -q -n "castle-fs"
for kvariant in %{kvariants} ; do
    cp -a kernel _kmod_build_$kvariant
done

%build
echo '%{version}-%{release}' > .hg-rev

make -C user/utils

for kvariant in %{kvariants}
do
    ksrc=%{_usrsrc}/kernels/%{kverrel}${kvariant:+-$kvariant}-%{_target_cpu}
    pushd _kmod_build_$kvariant
    make KVER=%{kversion} KERNEL_DIR="${ksrc}" DEBUG=n PERF_DEBUG=n %{?_smp_mflags}
    popd
done

mkdir -p tools/docs
(cd tools && doxygen Doxyfile.kernel)
(cd tools && doxygen Doxyfile.user)

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/etc/rc.d/init.d
mkdir -p %{buildroot}/etc/udev/rules.d/
mkdir -p %{buildroot}/etc/castle-fs
mkdir -p %{buildroot}/sbin
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/share/castle-fs
mkdir -p %{buildroot}/var/lib/castle-fs
cp user/udev/castle-fs.rules %{buildroot}/etc/udev/rules.d/
cp user/udev/udev-watch %{buildroot}/etc/castle-fs/
cp user/utils/castle %{buildroot}/etc/rc.d/init.d/
cp user/utils/castle_claim_empty %{buildroot}/etc/rc.d/init.d/
cp user/utils/init-utils %{buildroot}/usr/share/castle-fs/
cp user/utils/castle-fs-init.sh %{buildroot}/usr/share/castle-fs/castle-fs-init
cp user/utils/castle-fs-fini.sh %{buildroot}/usr/share/castle-fs/castle-fs-fini
cp user/utils/castle-smart-weigh-drive %{buildroot}/usr/sbin/
cp user/utils/castle-smart-spank-drive %{buildroot}/usr/sbin/
cp user/utils/castle-scan %{buildroot}/usr/sbin/
cp user/utils/castle_probe_device %{buildroot}/usr/sbin/castle-probe-device
cp user/utils/castle-create %{buildroot}/usr/sbin/
cp user/utils/castle-claim-empty %{buildroot}/usr/sbin/
cp user/utils/check-ssd %{buildroot}/usr/sbin/
cp user/utils/mkcastlefs %{buildroot}/sbin

export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
for kvariant in %{kvariants}
do
    ksrc=%{_usrsrc}/kernels/%{kverrel}${kvariant:+-$kvariant}-%{_target_cpu}
    pushd _kmod_build_$kvariant
    make -C "${ksrc}" modules_install M=$PWD
    popd
done

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add castle
/sbin/chkconfig --add castle_claim_empty

%preun
if [ $1 = 0 ] ; then
    /sbin/service castle stop >/dev/null 2>&1
    /sbin/chkconfig --del castle
    /sbin/chkconfig --del castle_claim_empty
fi

%pre
getent group %{groupname} >/dev/null || groupadd -r %{groupname}

%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/*
/etc/udev/rules.d
/etc/castle-fs/udev-watch
/usr/share/castle-fs
/usr/sbin/*
/sbin/mkcastlefs
/var/lib/castle-fs

%package doc

Summary: castle-fs documentation
Group: Documentation

%description doc

%files doc
%doc tools/docs/kernel
%doc tools/docs/user

%changelog
* Thu Sep  9 2010 Andrew Suffield <asuffield@acunu.com> - %{buildver}-%{buildrev}
- Initial package
