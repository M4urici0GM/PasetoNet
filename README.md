
[![Build Status](https://travis-ci.org/M4urici0GM/PasetoNet.svg?branch=master)](https://travis-ci.org/M4urici0GM/PasetoNet)

# PasetoNet
A [Paseto-dotnet](https://github.com/idaviddesmet/paseto-dotnet) extension for .netCore authentication.

## Dependencies:
- Newtonsoft.Json >= 12.0.2
- Paseto.Core >= 0.7.2
- FluentValidation >= 8.5.1

## Roadmap
- [x] Create Extension methods.
- [x] Token verification
- [x] Multiple claim support
- [x] Token generation
- [x] Refresh Tokens feature
- [x] Manual Token verification
- [x] Update to .netCore 3.0


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

## Generating tokens
```csharp

ClaimsIdentity identity = new ClaimsIdentity(
    new GenericIdentity(userUniqueIdentifier, nameOfIdentifier),
    new []
    {
        new Claim(PasetoRegisteredClaimsNames.TokenIdentifier, Guid.NewGuid().ToString("N")),
        //Add your claims here. e.g. new Claim("name", "value"),
    });

PasetoTokenDescriptor pasetoTokenDescriptor = new PasetoTokenDescriptor()
{
    Audience = audience,
    Expires = expirationDate,
    Issuer = issuer,
    Subject = identity,
    NotBefore = DateTime.Now,
    SecretKey = secretKey
};
PasetoTokenHandler tokenHandler = new PasetoTokenHandler();

//Write the token (awaitable)
string token = tokenHandler.WriteToken(pasetoTokenDescriptor);
```

## Decoding tokens
Sometimes you'll have to decode a token manually, so i implemented that feature to make your life easier:

```csharp

    //In the constructor of Controller:
    public UserController(IPasetoTokenHandler pasetoTokenHandler)
    {
        _pasetoTokenHandler = pasetoTokenHandler;
    }

    //In the method (async): 
    [HttpPost]
    public async IActionResult DecodeToken(string token) {
        ClaimsPrincipal claimsPrincipal = await _pasetoTokenHandler.DecodeTokenAsync(token);
    }

    //In the method (sync): 
    [HttpPost]
    public IActionResult DecodeToken(string token) {
        ClaimsPrincipal claimsPrincipal = _pasetoTokenHandler.DecodeTokenAsync(token).Result;
    }
```


# Tips: 
### The tips below are only tips and tricks, you can use them, or just follow your own style, i decided to put them here, 'cause in the beginning i suffered a lot to learn that.

## Blocking non-authenticated users globally:
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

## Working with multi-level authentication
You can also utilize claims to restrict user actions, see the example below:

In the Configure method, we're goin to put these lines: 
```csharp
public void Configure(IApplicationBuilder app)
{
    services.AddAuthorization(auth =>
        {
            auth.AddPolicy("Admin", policy => policy.RequireClaim("accessLevel", "admin"));
            auth.AddPolicy("User", policy => policy.RequireClaim("accessLevel", "user"));
        });
}
```
In the code above, we've created two policies, one called Admin wich requires the claim value "admin", and another called User wich requires the "user" value.

To restrict users, we first need to add these claims to the user tokens that we want to restrict:
```csharp
ClaimsIdentity identity = new ClaimsIdentity(
    new GenericIdentity(userUniqueIdentifier, nameOfIdentifier),
    new []
    {
        new Claim(PasetoRegisteredClaimsNames.TokenIdentifier, Guid.NewGuid().ToString("N")),
        new Claim("accessLevel", "admin")
    });

//The remaining token generating code
```
And then, to restrict routes, in the controller we're going to use:
```csharp
[HttpGet, Authorize("admin")]
public async Task<PaginableObject<UserDto>> GetUsers(int page = 1, int pageSize = 10)
{
    return await _mediator.Send(new GetUsers { Page = page, PageSize = pageSize });
}
```
The code above is actually a piece of real code on production, that i've made, as you can see, only authenticated users with the "admin" on "accessLevel" claim can access this endpoint".
To allow multiple claims in the same route, just add a comma between the policies:
```csharp
[HttpGet, Authorize("admin, user")]
```

## Using roles instead of Claim based system

```csharp
public void Configure(IApplicationBuilder app)
{
    services.AddAuthorization(auth =>
        {
            auth.AddPolicy("Admin", policy => policy.RequireRole("Administrator");
            //.. the remaining policies that you have
        });
}
```
Inside the array of claims in the token generation proccess, add: 
```csharp
    new Claim(ClaimTypes.Role, "admin")
```
 And finally on the controller endpoint, you`ll need to put the following code: 
```csharp
[HttpGet, Authorize(Roles = "Administrator")]
```
To allow multiple roles:
```csharp
[HttpGet, Authorize(Roles = "Administrator, MarketingAdmin")]
```