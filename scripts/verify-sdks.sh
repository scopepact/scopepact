#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v flutter >/dev/null 2>&1 || {
  echo "Flutter is required to verify sdks/flutter" >&2
  exit 1
}
command -v swift >/dev/null 2>&1 || {
  echo "Swift is required to verify sdks/swift" >&2
  exit 1
}
command -v go >/dev/null 2>&1 || {
  echo "Go is required to verify sdks/go" >&2
  exit 1
}
command -v cmake >/dev/null 2>&1 || {
  echo "CMake is required to verify sdks/cpp" >&2
  exit 1
}
command -v dotnet >/dev/null 2>&1 || {
  echo ".NET 8 is required to verify sdks/dotnet" >&2
  exit 1
}

(
  cd "$project_root/sdks/go"
  go test ./...
)

cmake -S "$project_root/sdks/cpp" -B "$project_root/sdks/cpp/build"
cmake --build "$project_root/sdks/cpp/build" --parallel
ctest --test-dir "$project_root/sdks/cpp/build" --output-on-failure

dotnet run \
  --project "$project_root/sdks/dotnet/tests/ScopePact.Envelope.Conformance"

(
  cd "$project_root/sdks/flutter"
  flutter pub get
  flutter test
)

swift test --package-path "$project_root/sdks/swift"
