@echo on

REM Builds the nghttp2 for STC for all Windows 64bit platform configurations. ;)
REM NOTICE: Follow instructions and change a few variables below before building.

REM Change STC_ROOT to the STC build root folder.
set STC_ROOT=C:\TestCenter\integration

REM NB: Do not link to STC OpenSSL libraries. Build OpenSSL from source or use vcpkg.
REM The nghttp2 build will perform a static link. To build OpenSSL from source, follow
REM the instructions in INSTALL.W64 for building the static libraries.
set OPENSSL_WIN64=C:\dev\openssl_64\openssl-1.0.1u

set BOOST_INCLUDEDIR=%STC_ROOT%\common\lib\boost_1_64_0
set BOOST_LIB_WIN64_DEBUG=%STC_ROOT%\framework\bll\lib\Win64\Debug
set BOOST_LIB_WIN64_RELEASE=%STC_ROOT%\framework\bll\lib\Win64\Release

set ZLIB_WIN64_DEBUG=%STC_ROOT%\framework\bll\lib\Win64\Debug\zlib_1D.lib
set ZLIB_WIN64_RELEASE=%STC_ROOT%\framework\bll\lib\Win64\Release\zlib_1.lib

set OPENSSL_ROOT_DIR=%OPENSSL_WIN64%

pushd C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\Tools
call VsDevCmd.bat -arch=x64
popd

@echo --------------------------------- BUILDING Win64 Release ----------------------------------

set BOOST_LIBRARYDIR=%BOOST_LIB_WIN64_RELEASE%

cmake . -A x64 -DCMAKE_BUILD_TYPE=Release -DENABLE_ASIO_LIB:BOOL="1" -DCMAKE_CXX_FLAGS="/EHsc" -DZLIB_LIBRARY=%ZLIB_WIN64_RELEASE% -DZLIB_INCLUDE_DIR=%STC_ROOT%\common\lib\zlib123 -DOPENSSL_ROOT_DIR=%OPENSSL_WIN64%\out32 -DOPENSSL_INCLUDE_DIR=%OPENSSL_WIN64%\inc32
cmake --build ..\. --config Release --clean-first

set BOOST_LIBRARYDIR=%BOOST_LIB_WIN64_DEBUG%

@echo --------------------------------- BUILDING Win64 Debug ----------------------------------

cmake . -A x64 -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASIO_LIB:BOOL="1" -DCMAKE_CXX_FLAGS="/EHsc" -DZLIB_LIBRARY=%ZLIB_WIN64_DEBUG% -DZLIB_INCLUDE_DIR=%STC_ROOT%\common\lib\zlib123 -DOPENSSL_ROOT_DIR=%OPENSSL_WIN64%\out32 -DOPENSSL_INCLUDE_DIR=%OPENSSL_WIN64%\inc32
cmake --build . --config Debug --clean-first

@echo --------------------------------- BUILDING nghttp2 completed ----------------------------------
