
[![Build Status](https://travis-ci.org/M4urici0GM/PasetoNet.svg?branch=master)](https://travis-ci.org/M4urici0GM/PasetoNet)

# PasetoNet
A [Paseto-dotnet](https://github.com/idaviddesmet/paseto-dotnet) extension for .netCore authentication.

## Dependencies:
- Newtonsoft.Json >= 12.0.2
- Paseto.Core >= 0.7.2

# Implementing on your code
```csharp
//Startup.cs

using PasetoAuth;
using PasetoAuth.Common;

public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
    {
        options.DefaultChallengeScheme = PasetoDefaults.Bearer;
        options.DefaultAuthenticateScheme = PasetoDefaults.Bearer;
    }).AddPaseto(options =>
    {
       //Secret key must have exactly 32 chars, otherwise it will throw an exception.
       options.SecretKey = SecretKey; 
    });
    
    //The rest of your code.
}

public void Configure(IApplicationBuilder app)
{
    app.UseAuthentication(); //You should call this BEFORE the AddMvc(); method.
    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
}
```

# Tips: 
I Personally prefer to block non-authenticated users in the entire application,
and allow anonymous routes on-demand, to make that happen, we need to create a filter telling to the authorization policy only allow authenticated users.

See the code below:
```csharp
public void Configure(IApplicationBuilder app)
{
    //...
    services.AddMvc(config =>
            {
                AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
                                             .RequireAuthenticatedUser()
                                             .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            }).SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
}
```
And then in the controller use the ```[AllowAnonymous] ``` annotation:
```csharp
[ApiController, Route("api/[controller]")]
public class UserController {

    [AllowAnonymous, Route("auth")]
    public Task<IActionResult> Authenticate([FromBody] string user, [FromBody] string password) {
        //Do the auth logic.
    }
}

```
 
## Roadmap
- [x] Create Extension methods.
- [x] Token verification
- [x] Multiple claim support
- [ ] Token generation
- [ ] Update to .netCore 3.0
