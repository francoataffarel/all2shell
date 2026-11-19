<?php
/**
 * Plugin Name: all2shell — Bloqueio da REST Batch API não autenticada
 * Description: Exige um usuário autenticado para a rota /batch/v1 do núcleo do WordPress.
 *              Mitigação temporária para a cadeia wp2shell (CVE-2026-63030, CVE-2026-60137)
 *              enquanto a atualização para 6.9.5 / 7.0.2 não é aplicada.
 * Version:     1.0.0
 * License:     GPL-2.0-or-later
 *
 * Instalação: copie este arquivo para wp-content/mu-plugins/ (carregamento automático,
 * sem ativação manual). Medida emergencial: consumidores legítimos que chamam a batch API
 * de forma anônima deixarão de funcionar. Remova após atualizar o WordPress.
 */

defined( 'ABSPATH' ) || exit;

add_filter(
	'rest_pre_dispatch',
	/**
	 * Rejeita chamadas anônimas à rota REST /batch/v1.
	 *
	 * @param mixed            $result  Resultado pré-calculado do dispatch (ou null).
	 * @param WP_REST_Server   $server  Instância do servidor REST (não utilizada).
	 * @param WP_REST_Request  $request Requisição REST atual.
	 * @return mixed|WP_Error
	 */
	function ( $result, $server, $request ) {
		unset( $server );

		$route = strtolower( untrailingslashit( (string) $request->get_route() ) );

		if ( '/batch/v1' !== $route || is_user_logged_in() ) {
			return $result;
		}

		return new WP_Error(
			'all2shell_batch_auth_required',
			'A REST batch API exige autenticação (mitigação wp2shell).',
			array( 'status' => 401 )
		);
	},
	-1000,
	3
);
