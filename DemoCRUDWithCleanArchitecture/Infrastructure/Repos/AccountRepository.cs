using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Domain.Entity.Authentication;
using Application.DTOs.Response;
using Application.Contracts;
using Application.DTOs.Request;
using Application.DTOs.Response;
using Application.DTOs.Request.Account;
using Application.DTOs.Response.Account;

namespace Infrastructure.Repos
{
    public class AccountRepository
        (RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager, IConfiguration config,
        SignInManager<ApplicationUser> signInManager) : IAccount
    {
        Task<GeneralResponse> IAccount.ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
        {
            throw new NotImplementedException();
        }

        Task<GeneralResponse> IAccount.CreateAccountAsync(CreateAccountDTO model)
        {
            throw new NotImplementedException();
        }

        Task IAccount.CreateAdmin()
        {
            throw new NotImplementedException();
        }

        Task<GeneralResponse> IAccount.CreateRoleAsync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        Task<IEnumerable<GetRoleDTO>> IAccount.GetRolesAsync()
        {
            throw new NotImplementedException();
        }

        Task<IEnumerable<GetUsersWithRolesResponseDTO>> IAccount.GetUsersWithRolesAsync()
        {
            throw new NotImplementedException();
        }

        Task<LoginResponse> IAccount.LoginAccountAsync(LoginDTO model)
        {
            throw new NotImplementedException();
        }
    }
}
