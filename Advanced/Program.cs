using Advanced.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

builder.Services.AddDbContext<DataContext>(opts =>
{
    opts.UseSqlServer(builder.Configuration["ConnectionStrings:PeopleConnection"]);
    opts.EnableSensitiveDataLogging(true);
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
.AddEntityFrameworkStores<DataContext>();

builder.Services.Configure<IdentityOptions>(opts =>
{
    opts.Password.RequiredLength = 3;
    opts.Password.RequireNonAlphanumeric = false;
    opts.Password.RequireLowercase = false;
    opts.Password.RequireUppercase = false;
    opts.Password.RequireDigit = false;
    opts.User.RequireUniqueEmail = true;
    //opts.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyz";
});

builder.Services.Configure<CookieAuthenticationOptions>(
IdentityConstants.ApplicationScheme,
opts =>
{
    opts.LoginPath = "/Account/Login";
    opts.AccessDeniedPath = "/Account/AccessDenied";
});

builder.Services.AddAuthentication(opts =>
{
    opts.DefaultScheme =
    CookieAuthenticationDefaults.AuthenticationScheme;
    opts.DefaultChallengeScheme =
    CookieAuthenticationDefaults.AuthenticationScheme;
}).AddCookie(opts =>
{
    opts.Events.DisableRedirectForPath(e => e.OnRedirectToLogin,
    "/api", StatusCodes.Status401Unauthorized);
    opts.Events.DisableRedirectForPath(e => e.OnRedirectToAccessDenied,
    "/api", StatusCodes.Status403Forbidden);
}).AddJwtBearer(opts =>
{
    opts.RequireHttpsMetadata = false;
    opts.SaveToken = true;
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
    Encoding.ASCII.GetBytes(builder.Configuration["jwtSecret"])),
        ValidateAudience = false,
        ValidateIssuer = false
    };
    opts.Events = new JwtBearerEvents
    {
        OnTokenValidated = async ctx =>
        {
            var usrmgr = ctx.HttpContext.RequestServices
            .GetRequiredService<UserManager<IdentityUser>>();
            var signinmgr = ctx.HttpContext.RequestServices
            .GetRequiredService<SignInManager<IdentityUser>>();
            string? username =
            ctx.Principal?.FindFirst(ClaimTypes.Name)?.Value;
            IdentityUser idUser = await usrmgr.FindByNameAsync(username);
            ctx.Principal =
            await signinmgr.CreateUserPrincipalAsync(idUser);
        }
    };
});

builder.Services.AddSingleton<Advanced.Services.ToggleService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapControllerRoute("controllers",
"controllers/{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.UseBlazorFrameworkFiles("/webassembly");
app.MapFallbackToFile("/webassembly/{*path:nonfile}", "/webassembly/index.html");

var context = app.Services.CreateScope().ServiceProvider
.GetRequiredService<DataContext>();
SeedData.SeedDatabase(context);
IdentitySeedData.CreateAdminAccount(app.Services, app.Configuration);

app.Run();
