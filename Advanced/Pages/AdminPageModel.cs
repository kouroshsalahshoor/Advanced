using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Advanced.Pages
{
    [Authorize(Roles = "Admins")]
    public class AdminPageModel : PageModel
    {
    }
}
