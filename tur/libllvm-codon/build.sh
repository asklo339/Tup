TERMUX_PKG_HOMEPAGE=https://github.com/exaloop/llvm-project
TERMUX_PKG_DESCRIPTION="Modular compiler and toolchain technologies library (Version 17, Codon Fork)"
TERMUX_PKG_LICENSE="Apache-2.0"
TERMUX_PKG_LICENSE_FILE="llvm/LICENSE.TXT"
TERMUX_PKG_MAINTAINER="@termux-user-repository"
_DATE=2024.01.21
TERMUX_PKG_VERSION=${_DATE//./}
_LLVM_COMMIT=c5a1d86495d28ab045258f120a8e2c9f3ef67a3b
TERMUX_PKG_SRCURL=https://github.com/exaloop/llvm-project/archive/${_LLVM_COMMIT}.zip
TERMUX_PKG_SHA256=db37e218bb62b261f9debb4bb526a4abb37af8ac9a7973099c6d9a99a3e424c6
TERMUX_PKG_HOSTBUILD=true
TERMUX_PKG_DEPENDS="libc++, ndk-sysroot, libffi"
TERMUX_PKG_SUGGESTS="codon"

_INSTALL_PREFIX_R="opt/codon"
_INSTALL_PREFIX="$TERMUX_PREFIX/$_INSTALL_PREFIX_R"
# See http://llvm.org/docs/CMake.html:
TERMUX_PKG_EXTRA_CONFIGURE_ARGS="
-DANDROID_PLATFORM_LEVEL=$TERMUX_PKG_API_LEVEL
-DPYTHON_EXECUTABLE=$(command -v python3)
-DLLVM_ENABLE_PIC=ON
-DLLVM_ENABLE_LIBEDIT=OFF
-DDEFAULT_SYSROOT=$(dirname $TERMUX_PREFIX)
-DLLVM_LINK_LLVM_DYLIB=on
-DLLVM_NATIVE_TOOL_DIR=$TERMUX_PKG_HOSTBUILD_DIR/bin
-DCROSS_TOOLCHAIN_FLAGS_LLVM_NATIVE=-DLLVM_NATIVE_TOOL_DIR=$TERMUX_PKG_HOSTBUILD_DIR/bin
-DLIBOMP_ENABLE_SHARED=FALSE
-DLLVM_ENABLE_SPHINX=ON
-DSPHINX_OUTPUT_MAN=ON
-DSPHINX_WARNINGS_AS_ERRORS=OFF
-DPERL_EXECUTABLE=$(command -v perl)
-DLLVM_TARGETS_TO_BUILD=all
-DLLVM_INSTALL_UTILS=OFF
-DLLVM_INCLUDE_TESTS=OFF
-DLLVM_ENABLE_FFI=ON
-DLLVM_ENABLE_RTTI=ON
-DLLVM_ENABLE_ZLIB=OFF
-DLLVM_ENABLE_TERMINFO=OFF
-DCMAKE_INSTALL_PREFIX=$_INSTALL_PREFIX
"

if [ $TERMUX_ARCH_BITS = 32 ]; then
	# Do not set _FILE_OFFSET_BITS=64
	TERMUX_PKG_EXTRA_CONFIGURE_ARGS+=" -DLLVM_FORCE_SMALLFILE_FOR_ANDROID=on"
fi

TERMUX_PKG_FORCE_CMAKE=true
TERMUX_PKG_HAS_DEBUG=false

termux_step_host_build() {
	termux_setup_cmake
	termux_setup_ninja

	cmake -G Ninja "-DCMAKE_BUILD_TYPE=Release" \
					$TERMUX_PKG_SRCDIR/llvm
	ninja -j $TERMUX_PKG_MAKE_PROCESSES llvm-tblgen llvm-min-tblgen
}

termux_step_pre_configure() {
	# Add unknown vendor, otherwise it screws with the default LLVM triple
	# detection.
	export LLVM_DEFAULT_TARGET_TRIPLE=${CCTERMUX_HOST_PLATFORM/-/-unknown-}
	export LLVM_TARGET_ARCH
	if [ $TERMUX_ARCH = "arm" ]; then
		LLVM_TARGET_ARCH=ARM
	elif [ $TERMUX_ARCH = "aarch64" ]; then
		LLVM_TARGET_ARCH=AArch64
	elif [ $TERMUX_ARCH = "i686" ] || [ $TERMUX_ARCH = "x86_64" ]; then
		LLVM_TARGET_ARCH=X86
	else
		termux_error_exit "Invalid arch: $TERMUX_ARCH"
	fi
	# see CMakeLists.txt and tools/clang/CMakeLists.txt
	TERMUX_PKG_EXTRA_CONFIGURE_ARGS+=" -DLLVM_TARGET_ARCH=$LLVM_TARGET_ARCH"
	TERMUX_PKG_EXTRA_CONFIGURE_ARGS+=" -DLLVM_HOST_TRIPLE=$LLVM_DEFAULT_TARGET_TRIPLE"
	_RPATH_FLAG="-Wl,-rpath=$TERMUX_PREFIX/lib"
	_RPATH_FLAG_ADD="-Wl,-rpath='\$ORIGIN/../lib' -Wl,-rpath=$TERMUX_PREFIX/lib"
	LDFLAGS="${LDFLAGS/$_RPATH_FLAG/$_RPATH_FLAG_ADD}"
	echo $LDFLAGS
	export TERMUX_SRCDIR_SAVE=$TERMUX_PKG_SRCDIR
	TERMUX_PKG_SRCDIR=$TERMUX_PKG_SRCDIR/llvm
}

termux_step_post_configure() {
	TERMUX_PKG_SRCDIR=$TERMUX_SRCDIR_SAVE
}
