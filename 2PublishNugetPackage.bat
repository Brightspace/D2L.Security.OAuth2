@if [%1]==[] goto usage

.nuget\nuget push %1 REDACTED-nuget-publish-key -s http://nuget.build.d2l/nuget/stable
goto :done

:usage
@echo Usage: %0 ^<nupkg_file_path^>

:done
@echo.
@pause
