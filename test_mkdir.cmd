@echo off
cd /d E:\code\windows-sandbox\win-sandbox\output
if exist fff_test_dir rmdir fff_test_dir
echo Testing mkdir in sandbox...
E:\code\windows-sandbox\win-sandbox\output\sandbox-host.exe --config E:\code\windows-sandbox\win-sandbox\config\default-sandbox.json exec cmd /c "mkdir fff_test_dir && echo CREATED || echo BLOCKED"
echo.
if exist fff_test_dir (
    echo RESULT: DIRECTORY WAS CREATED - NOT BLOCKED
) else (
    echo RESULT: DIRECTORY WAS BLOCKED
)
