using System.Security.Claims;
using Bff;
using Bff.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins("http://localhost:5173").AllowCredentials()));

builder.AddAuthentication();
// builder.Services.AddAuthorizationBuilder();

var app = builder.Build();

app.UseCors();

// Needed for chrome
app.UseCookiePolicy(new CookiePolicyOptions()
{
    Secure = CookieSecurePolicy.Always,
});

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
// app.UseAuthorization();

app.MapGet("/user", (HttpContext context) =>
{
    var user = context.User;
    var isAuthenticated = user.Identity?.IsAuthenticated ?? false;

    if (!isAuthenticated || user.Identity is null) return Results.Unauthorized();

    var claims = ((ClaimsIdentity)user.Identity).Claims.Select(c =>
            new { type = c.Type, value = c.Value })
        .ToArray();

    return Results.Ok(new { IsAuthenticated = isAuthenticated, Claims = claims });
});

app.MapGet("/login", (HttpContext context, [FromQuery] string? origin) =>
{
    var redirect = !string.IsNullOrEmpty(origin) ? $"/signin?origin={origin}" : "/signin";

    return Results.Challenge(new AuthenticationProperties { RedirectUri = redirect },
        new List<string> { "Auth0" });
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync();
    return Results.Redirect("/user");
});

app.MapGet("/signin", async (HttpContext context, [FromQuery] string? origin) =>
{
    var result = await context.AuthenticateAsync(AuthenticatonSchemes.ExternalScheme);

    if (!result.Succeeded)
        return Results.Unauthorized();

    var principal = result.Principal;

    var id = principal.FindFirstValue(ClaimTypes.NameIdentifier)!;
    var name = (principal.FindFirstValue(ClaimTypes.Email) ?? principal.Identity?.Name)!;
    var token = "im_a_fake_access_token_lol";

    // Write the login cookie
    await Signer.SignIn(id, name, token, "Auth0").ExecuteAsync(context);
    // await Signer.SignIn(context, id, name, token, "Auth0");

    // Delete the external cookie
    await context.SignOutAsync(AuthenticatonSchemes.ExternalScheme);

    var redirect = !string.IsNullOrEmpty(origin) ? origin : "/user";
    // TODO: Handle the failure somehow
    return Results.Redirect(redirect);
});

app.Run();