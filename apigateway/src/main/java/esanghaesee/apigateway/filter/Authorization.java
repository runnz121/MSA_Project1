package esanghaesee.apigateway.filter;


import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/*
* 로그는 추후 AOP로 수정 예정
* Gateway Token 추가
*/
@Component
@Slf4j
public class Authorization extends AbstractGatewayFilterFactory<Authorization.Config> {

	Environment env;

	public Authorization(Environment env) {
		super(Config.class);
		this.env = env;
	}

	public static class Config {

	}

	@Override
	public GatewayFilter apply(Config config) {
		return (((exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No Authorization", HttpStatus.UNAUTHORIZED);
			}
			String authHeader = request.getHeaders().get(org.springframework.http.HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authHeader.replace("Bearer ", "");
			if (!isJwtValid(jwt)) {
				return onError(exchange, "JWT token not valid", HttpStatus.UNAUTHORIZED);
			}
			return chain.filter(exchange);
		}));
	}

	private boolean isJwtValid(String jwt) {
		boolean returnValue = true;
		String subject = null;
		try {
			subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
				.parseClaimsJws(jwt).getBody()
				.getSubject();
		} catch (Exception ex) {
			returnValue = false;
		}
		if (subject == null || subject.isEmpty()) {
			returnValue = false;
		}
		return returnValue;
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);

		log.error(err);
		return response.setComplete();
	}
}


