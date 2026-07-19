package main

// outbound_proxy.go — исходящий SOCKS5-прокси для upstream-соединений
// (к датацентрам Telegram / Cloudflare-фоллбэку).
//
// Мотивация: позволяет направить исходящий трафик tg-ws-proxy через
// уже поднятый локальный SOCKS5-эндпоинт (например, Opera Proxy в
// -socks-mode на роутере) — то есть переиспользовать существующую
// прокси-инфраструктуру вместо того, чтобы городить отдельный
// tun2socks-мост. Названо TG_OUTBOUND_PROXY по аналогии с одноимённой
// переменной в tg-ws-proxy-rs (valnesfjord) — для единообразия среди
// разных реализаций одного и того же протокола, чтобы конфиг можно
// было переносить между ними без переучивания.
//
// Единая точка входа — dialUpstream(). Все места, которые раньше
// делали newUpstreamDialer(timeout).Dial(...)/.DialContext(...)
// напрямую, теперь идут через неё.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// buildOutboundDialer парсит cfg.OutboundProxy (пусто = без прокси) и
// возвращает proxy.ContextDialer. Вызывается один раз при старте (см.
// Config.outboundDialer, кэшируется — SOCKS5-дайлер из x/net/proxy не
// хранит состояния соединения, безопасно переиспользовать конкурентно
// между горутинами).
func buildOutboundDialer(rawURL string) (proxy.ContextDialer, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid --outbound-proxy URL: %w", err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		// Собственно ничего не отличаем между socks5/socks5h — резолв
		// доменов у нас никогда и не нужен на этом этапе: dialUpstream
		// всегда получает уже разрешённый IP (targetIP), а не домен.
	default:
		return nil, fmt.Errorf(
			"unsupported --outbound-proxy scheme %q (only socks5:// is supported)",
			u.Scheme)
	}

	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to build outbound proxy dialer: %w", err)
	}

	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// В x/net/proxy все встроенные дайлеры (включая SOCKS5)
		// реализуют ContextDialer, так что это защита от неожиданного
		// изменения в будущей версии зависимости, а не ожидаемый путь.
		return nil, fmt.Errorf(
			"outbound proxy dialer for scheme %q does not support context dialing",
			u.Scheme)
	}
	return cd, nil
}

// dialUpstream — единая точка выхода наружу (к DC Telegram или
// Cloudflare-фоллбэку). Если cfg.outboundDialer == nil — обычный прямой
// TCP-дайл (текущее поведение по умолчанию, без изменений). Если
// задан — весь трафик идёт через него.
func dialUpstream(ctx context.Context, cfg *Config, network, addr string, timeout time.Duration) (net.Conn, error) {
	if cfg == nil || cfg.outboundDialer == nil {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return newUpstreamDialer(timeout).DialContext(dctx, network, addr)
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return cfg.outboundDialer.DialContext(dctx, network, addr)
}
