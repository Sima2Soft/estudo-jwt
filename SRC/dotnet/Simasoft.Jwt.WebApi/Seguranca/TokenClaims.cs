using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Simasoft.Jwt.WebApi.Seguranca
{
    public class TokenClaims
    {
        /// <summary>
        /// A claim "iss" identifica quem emitiu o JWT, nossa, que descoberta!
        /// A forma como esta claim é gerada e processada é do domínio específico da aplicação.
        /// O valor atribuído para "iss" é uma string case-sensitive contendo um valor do tipo String ou URI.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// Exemplo: o endereço do site que está emitindo o JWT. exemplo: http://www.emissor.com
        /// </summary>        
        public string Issuer { get; set; }

        /// <summary>
        /// A claim "sub" identifica quem é a entidade no JWT, ou seja, qual é o usuário que estava logado no momento da emissão ou o usuário emissor ou o sistema logado em caso de integração.
        /// O valor de Subject PRECISA ter um valor único dentro do contexto do emissor ou ser único para todo os sistema.
        /// O processamento e validação desta claim é feito dentro da aplicação.
        /// O valor aceito por "sub" é uma string case-sensitive contendo um valor do tipo String ou URI.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// Exemplo: normalmente a conta de login única ou um id único do usuário.
        /// </summary>        
        public string Subject { get; set; }

        /// <summary>
        /// A claim "aud" (público-alvo) identifica os destinatários de uso do JWT.
        /// Cada entidade que é destinada a processar o JWT PRECISA identificar-se a si mesma colocando-se com um valor nesta claim.
        /// Se, durante o processamento e validação, esta claim não for identificada como a entidade a quem ela se destina, então o JWT PRECISA ser rejeitado. 
        /// Geralmente, o valr de "aud" é um array de strings case-sensitive, cada item contendo um valor do tipo String ou URI.
        /// Tal interpretação dos valores de "aud", são geralmente, específicos da aplicação.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// Exemplo:
        /// Não ficou muito claro o uso de "aud", certo? então, vamos facilitar com uma parábola.
        /// Eles são destinados a cenários em que você tem uma autoridade de emissão de token que não é o mesmo endereço ou dominio do aplicativo que é o destinatário pretendido, ou seja, que vai utilizá-lo. 
        /// Temos dois casos aqui:
        /// 2.1.3.1) Pense no Facebook.
        /// Para que você consiga rodar alguma aplicação sua dentro do facebook, você não precisa de um Token gigante?
        /// Então, o Facebook é a autoridade de emissão e a sua aplicação é o público alvo.
        /// Explicando ainda com mais detalhes:
        /// Considere um sistema grande.
        /// Você pode ter um servidor OAuth ou SSO que está emitindo os tokens, e um aplicativo que deseja um token que mostre que o servidor SSO verificou as credenciais do usuário e aprovou o usuário para usar o aplicativo. Nesse caso, você pode ter um token como "iss": "sso.example.com" e "aud": "aud.example.com", que se lê: O emissor sso.example.com gerou um token para ser utilizado por ou em aud.example.com.
        /// 2.1.3.2) Você pode gerar um token para um usuário e na "aud", você pode colocar todas as rotas, páginas e afins que ele pode acessar. 
        /// Pense na economia de requisição que você terá.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// A claim "nbf" identifica o tempo antes do qual o JWT NÃO DEVE ser aceito para processamento. 
        /// O processamento de "nbf" exige que a data/hora atual DEVE ser após ou igual ao valor de data/hora de "nbf".
        /// Desenvolvedores DEVEM permitir alguma margem de manobra pequna, geralmente não mais que alguns minutos para corrigir distorções de data/hora.
        /// O valor para "nbf" será um número contendo um tipo de NumericDate, um timestamp.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// </summary>        
        public DateTime NotBefore { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// A claim "iat" identifica a hora em que o JWT foi emitido.
        /// Esta claim pode ser utilizada para determinar a idade do JWT.
        /// O valor para "nbf" será um número contendo um tipo de NumericDate, um timestamp.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// </summary>        
        public DateTime IssuedAt { get; set; } = DateTime.UtcNow;
        
        public TimeSpan ValidFor { get; set; } = TimeSpan.FromDays(2);

        /// <summary>
        /// A claim "exp" identifica a data de validade onde após esta data, o JWT NÃO SERÁ aceito para processamento.
        /// A processamento de "exp" precisa que a data/hora seja anterior à data/hora de validade listada nela.
        /// Os desenvolvedores PRECISAM prover uma "margem de manobra" pequena, geralmente não maior que alguns minutos para compensar a distorção do relógio.
        /// O valor para "nbf" será um número contendo um tipo de NumericDate, um timestamp.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// </summary>
        public DateTime Expiration => IssuedAt.Add(ValidFor);

        /// <summary>
        /// A claim "jti" provê um identificador único para o JWT.
        /// O valor do identificador DEVE ser atribuído de maneira a garantir que exista uma probabilidade insignificante de que o mesmo valor seja acidentalmente atribuído a um objeto de dados diferente;
        /// Se a sua aplicação usar vários emissores, as colisões também devem ser evitadas entre os valores produzidos por diferentes emissores.
        /// "jti" pode ser usada para impedir que o JWT seja repetido.
        /// The "jti" value is a case-sensitive string.
        /// "jti" é uma string case-sensitive.
        /// O uso desta claim é opcional, como já foi dito antes.
        /// </summary>        
        public Func<Task<string>> JtiGenerator =>
          () => Task.FromResult(Guid.NewGuid().ToString());

        public SigningCredentials SigningCredentials { get; set; }
    }
}