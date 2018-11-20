using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Simasoft.Jwt.WebApi.Seguranca;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Simasoft.Jwt.WebApi.Controllers
{
    public class AccountController
    {
        private Customer _customer;
        private readonly TokenClaims _tokenOptions;
        private readonly JsonSerializerSettings _serializerSettings;
        private readonly ICustomerRepository _repository;
        private static long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970,1,1,0,0,0, TimeSpan.Zero)).TotalSeconds);
        
        public AccountController(IOptions<TokenClaims> jwtClaims, ICustomerRepository repository)
        {
            _repository = repository;
            _tokenOptions = jwtClaims.Value;
            ThrowIfInvalidOptions(_tokenOptions);

            //Converte o nome dos objetos no padrão do JSON
            //Falha no NewtonSoft.Json, talvez já tenham corrigido.
            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            };
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("v1/authenticate")]
        public async Task<IActionResult> Post([FromForm] AuthenticateUserCommand command)
        {
            if (command == null)
                return null;

            var identity = await GetClaims(command);            
            if (identity == null)
                return null;

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, command.Username),
                new Claim(JwtRegisteredClaimNames.NameId, command.Username),
                new Claim(JwtRegisteredClaimNames.Email, command.Username),
                new Claim(JwtRegisteredClaimNames.Sub, command.Username),
                new Claim(JwtRegisteredClaimNames.Jti, await _tokenOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_tokenOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst("NomeAplicacao")
            };

            var jwt = new JwtSecurityToken(
                issuer: _tokenOptions.Issuer,
                audience: _tokenOptions.Audience,
                claims: claims.AsEnumerable(),
                notBefore: _tokenOptions.NotBefore,
                expires: _tokenOptions.Expiration,
                signingCredentials: _tokenOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                token = encodedJwt,
                expires = (int)_tokenOptions.ValidFor.TotalSeconds,
                user = new
                {
                    id = _customer.Id,
                    name = _customer.Name.ToString(),
                    email = _customer.Email.Address,
                    username = _customer.User.Username
                }
            };

            var json = JsonConvert.SerializeObject(response, _serializerSettings);
            return new OkObjectResult(json);
            
        }

        //Pode Implementar assim
        private Task<ClaimsIdentity> GetClaims(AuthenticateUserCommand command)
        {
            var customer = _repository.GetByUserName(command.Username);

            if (customer == null)
                return Task.FromResult<ClaimsIdentity>(null);
            
            if (!customer.User.Authenticate(command.Username, command.Password))
            {
                return Task.FromResult<ClaimsIdentity>(null);
            }

            _customer = customer;

            return Task.FromResult(new ClaimsIdentity(
                new GenericIdentity(customer.User.Username,"Token"),
                new[]{
                    //new Claim("TES", customer.User.Role.ToString())
                    new Claim("NomeAplicacao","User"),  //Mesmo valor que demos às Policies
                    new Claim("NomeAplicacao","Admin")  //Mesmo valor que demos às Policies
                }));
        }

        //Também pode implementar assim    
        private Task<ClaimsIdentity> GetClaims(string username, string password){
            var customer = _repository.Get(username);

            if (customer == null)
                return Task.FromResult<ClaimsIdentity>(null);

            if (!customer.User.Authenticate(username, password))
            {
                return Task.FromResult<ClaimsIdentity>(null);
            }

            return Task.FromResult(new ClaimsIdentity(
                new GenericIdentity(customer.User.Username,"Token"),
                new[]{
                    //new Claim("TES", customer.User.Role.ToString())
                    new Claim("NomeAplicacao","User"),  //Mesmo valor que demos às Policies
                    new Claim("NomeAplicacao","Admin")  //Mesmo valor que demos às Policies
                }));
        }

        private static void ThrowIfInvalidOptions(TokenClaims options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
                throw new ArgumentException("O período deve ser maior que zero", nameof(TokenClaims.ValidFor));

            if (options.SigningCredentials == null)
                throw new ArgumentNullException(nameof(TokenClaims.SigningCredentials));

            if (options.JtiGenerator == null)
                throw new ArgumentNullException(nameof(TokenClaims.JtiGenerator));
        }


    }

    #region Mock Objects

    //Localização: Dominio.Contratos.Repositorios
    //Localization: Domain.Contracts.Repositories
    public interface ICustomerRepository
    {
        Customer Get(string username);
        Customer GetByUserName(string username);
    }

    public class Customer
    {
        public User User { get; set; }
        public string Id { get; internal set; }
        public string Name { get; internal set; }
        public Email Email { get; internal set; }
    }

    public class Email
    {
        internal string Address;
    }

    //Localização: Dominio.Comandos.Entradas
    //Localization: Domain.Commands.Inputs
    public class AuthenticateUserCommand : ICommand
    {
        public string Username {get; set;}
        public string Password {get; set;}
    }

    //Localização: CrossCutting.Comados
    //Localization: CrossCutting.Commands
    public interface ICommand
    {

    }

    public class User : Entity
    {
        protected User() { }

        public User(string username, string password, string confirmPassword)
        {
            Username = username;
            Password = EncryptPassword(password);
            Active = true;     
        }

        public string Username { get; private set; }
        public string Password { get; private set; }
        public bool Active { get; private set; }

        public bool Authenticate(string username, string password)
        {
            if (Username == username && Password == EncryptPassword(password))
                return true;

            return false;
        }

        public void Activate() => Active = true;
        public void Deactivate() => Active = false;

        private string EncryptPassword(string pass)
        {
            if (string.IsNullOrEmpty(pass)) return "";
            var password = (pass += "|2d331cca-f6c0-40c0-bb43-6e32989c2881");
            var sha256 = System.Security.Cryptography.SHA256.Create();
            var data = sha256.ComputeHash(Encoding.Default.GetBytes(password));
            var sbString = new StringBuilder();
            foreach (var t in data)
                sbString.Append(t.ToString("x2"));

            return sbString.ToString();
        }
    }

    public abstract class Entity
    {
        protected Entity()
        {
            Id = Guid.NewGuid();
        }

        public Guid Id { get; private set; }
    }

    #endregion

}
