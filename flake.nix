{
  description = "DigitalSign Architectural Classification System (DS) in RDF format";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustup
            openssl
            zlib
            curl
          ];

          # macOS specific dependencies if needed, or other common rust deps
          # pkg-config and openssl are often needed for Rust projects
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          shellHook = ''
            echo "Rust development environment with rustup loaded."
            echo "Run 'rustup default stable' if you haven't installed a toolchain yet."
            rustup default stable
          '';
        };
      }
    );
}