using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Simasoft.Jwt.WebApi.Seguranca;

namespace Simasoft.Jwt.WebApi
{
    public class Startup
    {
        //TODO: Converter isso em uma função para gerar este valor;
        private const string ISSUER = "c1f51f42";

        /*TODO: Criar uma WebAPI que gere este valor de Audience.
        Basta entrarmos uma String e então o Sistema converte via HMAC, RSA e etc
        E ai colocamos aqui.
        */
        private const string AUDIENCE = "c6bbbb645024";

        //TODO: Criar um método que gere esta Secret Key
        private const string SECRET_KEY = "c1f51f42-5727-4d15-b787-c6bbbb645024";

        //CRIANDO A CHAVE ASSIMÉTRICA
        private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SECRET_KEY));

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {            
            services.AddMvc(config => 
            {
                //Configurando as Policies no MVC
                //Fechando completamente a WebAPI
                //Bloqueando todos os acessos
                //E depois utiliza [AllowAnonymous] ou [Authenticate]
                //para liberar acesso aos métodos das Controllers
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                config.Filters.Add(new AuthorizeFilter(policy));    
            });

            //Habilitando o CORS
            services.AddCors();            

            //Adicionando as políticas por papel de usuário e as Claims específicas
            services.AddAuthorization(options =>
            {
                options.AddPolicy("User", policy => policy.RequireClaim("NomeAplicacao", "User"));
                options.AddPolicy("Admin",policy => policy.RequireClaim("NomeAplicacao","Admin"));
                options.AddPolicy("Admin", policy => 
                {
                    //Executar qualquer tarefa
                });
            });

            //Configurando a Autenticação
            services.Configure<TokenClaims>(options => 
            {
                options.Issuer = ISSUER;
                options.Audience = AUDIENCE;
                options.SigningCredentials = new SigningCredentials(_signingKey,SecurityAlgorithms.HmacSha256);
            });            

            //Valida o Token que foi gerado!
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = ISSUER, //TODO: CRIAR UM ISSUER DINÂMICO

                ValidateAudience = true,
                ValidAudience = AUDIENCE,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,

                ClockSkew = TimeSpan.Zero
            };

            //NOVA AUTENTICAÇÃO DE TOKEN BEARER .NET 2.0
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.Audience = AUDIENCE;
                options.ClaimsIssuer = ISSUER;
                options.TokenValidationParameters = tokenValidationParameters;
                options.SaveToken = true;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();

            /* MOVIDO PARA O METODO ConfigureServices
            //Valida o Token que foi gerado!
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = ISSUER, //TODO: CRIAR UM ISSUER DINÂMICO

                ValidateAudience = true,
                ValidAudience = AUDIENCE,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,

                ClockSkew = TimeSpan.Zero
            };
            */

            /* OBSOLETO
            TODO: Atualizar o projeto do professor Balta no Github
            VIA: https://github.com/aspnet/Security/issues/1310
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                TokenValidationParameters = tokenValidationParameters
            });
            */
            //Válido para o aspnet core 2.0
            
            
            app.UseCors(x => 
            {
                x.AllowAnyHeader();
                x.AllowAnyMethod();
                x.AllowAnyOrigin();
            });
            app.UseMvc();
            
        }
    }
}
