{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:
let
  name = "dfguard";

  pkg = config.languages.rust.import ./. { };
in
{
  cachix.enable = true;
  cachix.pull = [ "m00nwtchr" ];

  packages =
    with pkgs;
    [
    ]
    ++ (lib.optionals (!config.container.isBuilding) [
      git
      cargo-nextest
      cargo-audit
    ])
    ++ lib.optionals (!config.containers."prod".isBuilding) [ pkg ];

  containers."prod" = {
    inherit name;

    copyToRoot = "${pkg}/bin/${name}";
    startupCommand = "/${name}";
  };

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    mold.enable = true;
  };

  # https://devenv.sh/services/
  services.redis = {
    enable = true;
    package = pkgs.valkey;
  };

  treefmt = {
    enable = true;
    config.programs = {
      nixfmt.enable = true;
      rustfmt.enable = true;
    };
  };

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    treefmt.enable = true;
    clippy.enable = true;
  };

  outputs = {
    ${name} = pkg;
  };

  # See full reference at https://devenv.sh/reference/options/
}
