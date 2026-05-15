package io.kafbat.ui.config.auth;

import io.kafbat.ui.config.auth.logout.OAuthLogoutSuccessHandler;
import io.kafbat.ui.service.rbac.AccessControlService;
import io.kafbat.ui.service.rbac.extractor.ProviderAuthorityExtractor;
import io.kafbat.ui.service.rbac.extractor.RbacActiveDirectoryAuthoritiesExtractor;
import io.kafbat.ui.service.rbac.extractor.RbacLdapAuthoritiesExtractor;
import io.kafbat.ui.util.CustomSslSocketFactory;
import io.kafbat.ui.util.StaticFileWebFilter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.ad.DefaultActiveDirectoryAuthoritiesPopulator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@Configuration
@ConditionalOnProperty(value = "auth.type", havingValue = "OAUTH2_AND_LDAP")
@EnableConfigurationProperties({OAuthProperties.class, LdapProperties.class})
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class MultiAuthSecurityConfig extends AbstractAuthSecurityConfig {

  private static final Map<String, Object> LDAP_SSL_ENV_PROPS = Map.of(
      "java.naming.ldap.factory.socket", CustomSslSocketFactory.class.getName()
  );

  private final OAuthProperties oauthProperties;
  private final LdapProperties ldapProperties;

  // ==================== COMBINED SECURITY CHAIN ====================

  @Bean
  public SecurityWebFilterChain securityFilterChain(
      ServerHttpSecurity http,
      @Qualifier("multiLdapAuthManager") ReactiveAuthenticationManager ldapAuthManager,
      OAuthLogoutSuccessHandler logoutHandler,
      ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient,
      ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService,
      ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService,
      @Qualifier("oauthWebClient") WebClient webClient
  ) {
    log.info("Configuring multi-auth: OAUTH2 + LDAP simultaneously.");

    var oidcAuthManager =
        new OidcAuthorizationCodeReactiveAuthenticationManager(tokenResponseClient, oidcUserService);
    oidcAuthManager.setJwtDecoderFactory(reg ->
        NimbusReactiveJwtDecoder.withJwkSetUri(reg.getProviderDetails().getJwkSetUri())
            .webClient(webClient)
            .build());

    var oauth2AuthManager =
        new OAuth2LoginReactiveAuthenticationManager(tokenResponseClient, oauth2UserService);

    var delegatingOAuth2Manager =
        new DelegatingReactiveAuthenticationManager(oidcAuthManager, oauth2AuthManager);

    var builder = http
        .authorizeExchange(spec -> spec
            .pathMatchers(AUTH_WHITELIST).permitAll()
            .anyExchange().authenticated()
        )
        .formLogin(form -> form
            .loginPage(LOGIN_URL)
            .authenticationManager(ldapAuthManager)
            .authenticationSuccessHandler(emptyRedirectSuccessHandler())
        )
        .oauth2Login(oauth2 -> oauth2.authenticationManager(delegatingOAuth2Manager))
        .logout(spec -> spec
            .logoutSuccessHandler(logoutHandler)
            .requiresLogout(ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/logout"))
        )
        .csrf(ServerHttpSecurity.CsrfSpec::disable);

    builder.addFilterAt(new StaticFileWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING);

    return builder.build();
  }

  // ==================== LDAP BEANS ====================

  @Bean(name = "multiLdapAuthManager")
  public ReactiveAuthenticationManager multiLdapAuthManager(AbstractLdapAuthenticationProvider ldapAuthProvider) {
    return new ReactiveAuthenticationManagerAdapter(new ProviderManager(List.of(ldapAuthProvider)));
  }

  @Bean
  public AbstractLdapAuthenticationProvider ldapAuthProvider(
      LdapAuthoritiesPopulator ldapAuthoritiesPopulator,
      @Autowired(required = false) BindAuthenticator bindAuthenticator,
      AccessControlService acs) {
    AbstractLdapAuthenticationProvider authProvider;

    if (ldapProperties.isActiveDirectory()) {
      authProvider = activeDirectoryProvider(ldapAuthoritiesPopulator);
    } else {
      authProvider = new LdapAuthenticationProvider(bindAuthenticator, ldapAuthoritiesPopulator);
    }

    if (acs.isRbacEnabled()) {
      authProvider.setUserDetailsContextMapper(new RbacUserDetailsMapper());
    }

    return authProvider;
  }

  @Bean
  @ConditionalOnProperty(value = "oauth2.ldap.activeDirectory", havingValue = "false", matchIfMissing = true)
  public BindAuthenticator bindAuthenticator(LdapContextSource ldapContextSource) {
    BindAuthenticator ba = new BindAuthenticator(ldapContextSource);

    if (ldapProperties.getBase() != null) {
      ba.setUserDnPatterns(new String[]{ldapProperties.getBase()});
    }

    if (ldapProperties.getUserFilterSearchFilter() != null) {
      LdapUserSearch userSearch = new FilterBasedLdapUserSearch(
          ldapProperties.getUserFilterSearchBase(),
          ldapProperties.getUserFilterSearchFilter(),
          ldapContextSource);
      ba.setUserSearch(userSearch);
    }

    return ba;
  }

  @Bean
  public LdapContextSource ldapContextSource() {
    LdapContextSource ctx = new LdapContextSource();
    ctx.setUrl(ldapProperties.getUrls());
    ctx.setUserDn(ldapProperties.getAdminUser());
    ctx.setPassword(ldapProperties.getAdminPassword());
    ctx.afterPropertiesSet();
    return ctx;
  }

  @Bean
  public LdapAuthoritiesPopulator ldapAuthoritiesPopulator(
      ApplicationContext ctx,
      BaseLdapPathContextSource ldapCtx,
      AccessControlService acs) {
    if (!ldapProperties.isActiveDirectory()) {
      if (!acs.isRbacEnabled()) {
        return new NullLdapAuthoritiesPopulator();
      }
      var extractor = new RbacLdapAuthoritiesExtractor(ctx, ldapCtx, ldapProperties.getGroupFilterSearchBase());
      Optional.ofNullable(ldapProperties.getGroupFilterSearchFilter()).ifPresent(extractor::setGroupSearchFilter);
      extractor.setRolePrefix("");
      extractor.setConvertToUpperCase(false);
      extractor.setSearchSubtree(true);
      return extractor;
    } else {
      return acs.isRbacEnabled()
          ? new RbacActiveDirectoryAuthoritiesExtractor(ctx)
          : new DefaultActiveDirectoryAuthoritiesPopulator();
    }
  }

  private ActiveDirectoryLdapAuthenticationProvider activeDirectoryProvider(LdapAuthoritiesPopulator populator) {
    if (StringUtils.isBlank(ldapProperties.getActiveDirectoryDomain())) {
      throw new IllegalArgumentException("Active Directory domain is required but not specified");
    }

    var provider = new ActiveDirectoryLdapAuthenticationProvider(
        ldapProperties.getActiveDirectoryDomain(),
        ldapProperties.getUrls()
    );
    provider.setUseAuthenticationRequestCredentials(true);
    provider.setAuthoritiesPopulator(populator);

    if (Stream.of(ldapProperties.getUrls().split(",")).anyMatch(url -> url.startsWith("ldaps://"))) {
      provider.setContextEnvironmentProperties(LDAP_SSL_ENV_PROPS);
    }

    return provider;
  }

  private static class RbacUserDetailsMapper extends LdapUserDetailsMapper {
    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
                                          Collection<? extends GrantedAuthority> authorities) {
      return new RbacLdapUser(super.mapUserFromContext(ctx, username, authorities));
    }
  }

  // ==================== OAUTH2 BEANS ====================

  @Bean(name = "oauthWebClient")
  public WebClient oauthWebClient() {
    return WebClient.builder()
        .clientConnector(new ReactorClientHttpConnector(HttpClient.create().proxyWithSystemProperties()))
        .build();
  }

  @Bean
  public ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient(@Qualifier("oauthWebClient") WebClient webClient) {
    var client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
    client.setWebClient(webClient);
    return client;
  }

  @Bean
  public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService(
      AccessControlService acs,
      ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
    final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();
    delegate.setOauth2UserService(oauth2UserService);

    return request -> delegate.loadUser(request)
        .flatMap(user -> {
          var provider = oauthProperties.getClient().get(request.getClientRegistration().getRegistrationId());
          var extractor = getOAuthExtractor(provider, acs);
          if (extractor == null) {
            return Mono.just(user);
          }
          return extractor.extract(acs, user, Map.of("request", request, "provider", provider))
              .map(groups -> new RbacOidcUser(user, groups));
        });
  }

  @Bean
  public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> customOauth2UserService(
      AccessControlService acs, @Qualifier("oauthWebClient") WebClient webClient) {
    final DefaultReactiveOAuth2UserService delegate = new DefaultReactiveOAuth2UserService();
    delegate.setWebClient(webClient);

    return request -> delegate.loadUser(request)
        .flatMap(user -> {
          var provider = oauthProperties.getClient().get(request.getClientRegistration().getRegistrationId());
          var extractor = getOAuthExtractor(provider, acs);
          if (extractor == null) {
            return Mono.just(user);
          }
          return extractor.extract(acs, user, Map.of("request", request, "provider", provider))
              .map(groups -> new RbacOAuth2User(user, groups));
        });
  }

  @Bean
  public InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
    final OAuth2ClientProperties props = OAuthPropertiesConverter.convertProperties(oauthProperties);
    final List<ClientRegistration> registrations =
        new ArrayList<>(new OAuth2ClientPropertiesMapper(props).asClientRegistrations().values());
    if (registrations.isEmpty()) {
      throw new IllegalArgumentException("No OAuth2 providers configured for OAUTH2_AND_LDAP auth.");
    }
    return new InMemoryReactiveClientRegistrationRepository(registrations);
  }

  @Bean
  public ServerLogoutSuccessHandler defaultOidcLogoutHandler(ReactiveClientRegistrationRepository repository) {
    return new OidcClientInitiatedServerLogoutSuccessHandler(repository);
  }

  private ProviderAuthorityExtractor getOAuthExtractor(OAuthProperties.OAuth2Provider provider,
                                                       AccessControlService acs) {
    return acs.getOauthExtractors()
        .stream()
        .filter(e -> e.isApplicable(provider.getProvider(), provider.getCustomParams()))
        .findFirst()
        .orElse(null);
  }
}
