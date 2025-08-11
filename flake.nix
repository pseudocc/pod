{
  description = ": Zig development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }: import ./nix/each-system.nix nixpkgs (
    system: pkgs: {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          zig
          zls
        ];
      };
    }
  );
}
