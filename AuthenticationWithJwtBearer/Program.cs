using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Authentication:Schemes:Bearer:ValidIssuer"],
            ValidAudience = builder.Configuration["Authentication:Schemes:Bearer:ValidAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtKey"]))
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Administrator", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", (HttpContext httpContext) =>
{
    var username = httpContext.Request.Form["username"];
    var password = httpContext.Request.Form["password"];
    var securityTokenHandler = new JwtSecurityTokenHandler();
    if (username == "admin" && password == "password")
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Email,"bruce@abc.com"),
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(ClaimTypes.Name, username)
        };

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(app.Configuration["JwtKey"]));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
                    app.Configuration["Authentication:Schemes:Bearer:ValidIssuer"],
                    builder.Configuration["Authentication:Schemes:Bearer:ValidAudience"],
                    claims,
                    null,
                    DateTime.Now.AddMinutes(20),
                    signingCredentials);

        return Results.Ok(securityTokenHandler.WriteToken(token));
    }
    return Results.Unauthorized();
});

app.MapGet("/protected", () =>
{
    return "This is a protected API";
}).RequireAuthorization("Administrator");

app.Run();