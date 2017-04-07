# D2L.Security.OAuth2

| Platform   | Build status |
|------------|--------------|
| Windows    | [![Windows](https://ci.appveyor.com/api/projects/status/id5byt9yitcek417/branch/master?svg=true)](https://ci.appveyor.com/project/Brightspace/d2l-security-oauth2/branch/master) |
| Linux+Mono | [![Linux](https://travis-ci.org/Brightspace/D2L.Security.OAuth2.svg?branch=master)](https://travis-ci.org/Brightspace/D2L.Security.OAuth2) |

C# libraries for integrating with Brightspace OAuth 2.0.

## Libraries

The libraries in this repository are published in lock-step. It is recommended that you maintain a consistent version number on any of these that you depend on. Mixing versions as of the version 5.0 release is not supported.

### D2L.Security.OAuth2
[![NuGet](https://img.shields.io/nuget/v/D2L.Security.OAuth2.svg?maxAge=7200)](https://www.nuget.org/packages/D2L.Security.OAuth2/)

Core functionality for request validation and token provisioning.

### D2L.Security.OAuth2.WebApi
[![NuGet](https://img.shields.io/nuget/v/D2L.Security.OAuth2.WebApi.svg?maxAge=7200)](https://www.nuget.org/packages/D2L.Security.OAuth2.WebApi/)

WebAPI integration in the form of filters/attributes/etc.

### D2L.Security.OAuth2.TestFramework
[![NuGet](https://img.shields.io/nuget/v/D2L.Security.OAuth2.TestFramework.svg?maxAge=7200)](https://www.nuget.org/packages/D2L.Security.OAuth2.TestFramework/)

Helper library for writing tests.

## Contributing

1. **Fork** the repository. Committing directly against this repository is
   highly discouraged.

2. Make your modifications in a branch, updating and writing new tests.

3. Ensure that all tests pass

4. `rebase` your changes against master. *Do not merge*.

5. Submit a pull request to this repository. Wait for tests to run and someone
   to chime in.
