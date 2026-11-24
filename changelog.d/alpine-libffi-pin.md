### Fixed
- The API image builds again: Alpine 3.23 replaced `libffi-dev` 3.5 with 3.8.1, so the build stage's `libffi-dev~=3.5` pin could no longer be satisfied and every image build failed. The pin now tracks 3.8.
