{
  description = "hathor-ct-crypto-wasm dev shell — Rust + wasm-pack + unwrapped clang for the wasm32 build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        # Unwrapped clang (raw upstream LLVM with the wasm32 backend
        # built in). Required because nix's *wrapped* clang injects
        # host-only flags like `-fzero-call-used-regs=used-gpr` that the
        # wasm32 backend rejects, and `emcc` refuses bare
        # `wasm32-unknown-unknown` outright (it only supports
        # `wasm32-unknown-emscripten`). secp256k1-sys ships its own
        # minimal `wasm/wasm-sysroot/`, so we don't need wasi-libc on
        # top — just clang with the wasm32 target.
        clangUnwrapped = pkgs.llvmPackages.clang-unwrapped;
        llvmAr = "${pkgs.llvmPackages.bintools-unwrapped}/bin/llvm-ar";
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Bundler for the WASM build of `@hathor/ct-crypto-wasm`:
            # drives `cargo build --target wasm32-unknown-unknown` plus
            # wasm-bindgen post-processing and writes the npm-ready
            # `pkg/` artifact.
            wasm-pack
            # Cross-compiler for the bundled libsecp256k1 C source. See
            # the comment on `clangUnwrapped` above for why we can't use
            # the nix-wrapped clang or emscripten here.
            clangUnwrapped
            llvmPackages.bintools-unwrapped
            # rustup is intentionally left out — we let the user's
            # preferred Rust toolchain take precedence. The shell only
            # injects what cargo can't resolve on its own (wasm-pack,
            # unwrapped clang, llvm-ar).
          ];

          # Pin cc-rs's per-target compiler/archiver to the unwrapped
          # binaries. Without these, cc-rs falls through to the
          # nix-wrapped `clang` from $PATH (which is correct for the
          # host build but wrong for the wasm32 cross-compile).
          shellHook = ''
            export CC_wasm32_unknown_unknown=${clangUnwrapped}/bin/clang
            export AR_wasm32_unknown_unknown=${llvmAr}
            echo "[hathor-ct-crypto-wasm devShell] wasm-pack=$(which wasm-pack)"
            echo "[hathor-ct-crypto-wasm devShell] CC_wasm32_unknown_unknown=$CC_wasm32_unknown_unknown"
            echo "[hathor-ct-crypto-wasm devShell] AR_wasm32_unknown_unknown=$AR_wasm32_unknown_unknown"
          '';
        };
      });
}
