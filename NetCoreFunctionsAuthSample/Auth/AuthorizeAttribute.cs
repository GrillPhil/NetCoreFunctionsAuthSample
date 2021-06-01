using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host;
using System.Threading;
using System.Threading.Tasks;

namespace NetCoreFunctionsAuthSample.Auth
{
#pragma warning disable CS0618 // Type or member is obsolete
    internal class AuthorizeAttribute : FunctionInvocationFilterAttribute
#pragma warning restore CS0618 // Type or member is obsolete
    {
        private string[] _validAppRoles;

        public AuthorizeAttribute(params string[] validAppRoles)
        {
            _validAppRoles = validAppRoles;
        }

#pragma warning disable CS0618 // Type or member is obsolete
        public override async Task OnExecutingAsync(FunctionExecutingContext executingContext, CancellationToken cancellationToken)
#pragma warning restore CS0618 // Type or member is obsolete
        {
            var request = (HttpRequest)executingContext.Arguments["req"];
            var user = await AuthorizationHandler.ValidateRequestAsync(request, executingContext.Logger);
            var userIsAuthorized = user != null &&
                                    (_validAppRoles.Length == 0 ||
                                     AuthorizationHandler.UserIsInAppRole(user, _validAppRoles));

            if (userIsAuthorized)
            {
                request.HttpContext.User.AddIdentities(user.Identities);
            }
            else
            {
                request.HttpContext.Response.StatusCode = 401;
                await request.HttpContext.Response.Body.FlushAsync();
                request.HttpContext.Response.Body.Close();
                throw new UnauthorizedException();
            }
        }
    }
}
