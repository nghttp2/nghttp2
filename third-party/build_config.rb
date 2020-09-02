MRuby::Build.new do |conf|
  toolchain :clang if ENV['CC'].include? "clang"
  toolchain :gcc if ENV['CC'].include? "gcc"

  # C++ project needs this.  Without this, mruby exception does not
  # properly destory C++ object allocated on stack.
  conf.enable_cxx_exception

  conf.build_dir = ENV['BUILD_DIR']

  # include the default GEMs
  conf.gembox 'default'
  conf.gem :core => 'mruby-eval'
end
