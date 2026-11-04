"""
Post-build wheel cleanup: remove .py and .c source files for compiled core IP modules.
This ensures the distributed wheel contains only compiled binaries for core modules.
"""
import zipfile
import os
import glob
import sys

# Core IP modules to protect
CORE_MODULES = [
    'agentcore_tip/core/context',
    'agentcore_tip/core/credentials',
    'agentcore_tip/core/hooks',
    'agentcore_tip/core/strategies/sso_oidc',
    'agentcore_tip/core/strategies/web_identity',
]

# Build list of files to remove from wheel
FILES_TO_REMOVE = []
for module in CORE_MODULES:
    FILES_TO_REMOVE.append(module + '.py')
    FILES_TO_REMOVE.append(module + '.c')

# Find the wheel file
dist_dir = sys.argv[1] if len(sys.argv) > 1 else 'dist'
wheel_files = glob.glob(os.path.join(dist_dir, '*.whl'))

if not wheel_files:
    print('WARNING: No wheel file found in {}/'.format(dist_dir))
    sys.exit(1)

wheel_path = wheel_files[0]
temp_wheel = wheel_path + '.tmp'

removed_count = 0
with zipfile.ZipFile(temp_wheel, 'w', zipfile.ZIP_DEFLATED) as new_zip:
    with zipfile.ZipFile(wheel_path, 'r') as old_zip:
        for item in old_zip.filelist:
            if item.filename not in FILES_TO_REMOVE:
                new_zip.writestr(item, old_zip.read(item.filename))
            else:
                removed_count += 1

os.replace(temp_wheel, wheel_path)
print('Removed {} source files from wheel'.format(removed_count))
print('Protected modules:')
for module in CORE_MODULES:
    print('  - ' + module.replace('/', '.'))