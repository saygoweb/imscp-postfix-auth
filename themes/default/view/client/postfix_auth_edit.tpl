<form name="postfix_auth_edit" method="post"
      action="postfix_auth_edit.php?type={TYPE}&amp;id={ID}">

    <table class="firstColFixed">
        <thead>
        <tr><th colspan="2">{DOMAIN_NAME} &mdash; {TR_DNS_SECTION}</th></tr>
        </thead>
        <tbody>
        <tr>
            <td>
                <label for="publish_dns">{TR_PUBLISH_DNS}</label>
                <span class="icon i_help" title="{TR_PUBLISH_DNS_HELP}">?</span>
            </td>
            <td><input type="checkbox" name="publish_dns" id="publish_dns"{PUBLISH_DNS}></td>
        </tr>
        </tbody>
    </table>

    <table class="firstColFixed">
        <thead>
        <tr><th colspan="2">{TR_DKIM_SECTION}</th></tr>
        </thead>
        <tbody>
        <tr>
            <td colspan="2"><div class="info">{TR_DKIM_INTRO} {TR_SUBDOMAIN_NOTE}</div></td>
        </tr>
        <tr>
            <td><label for="dkim_enabled">{TR_DKIM_ENABLED}</label></td>
            <td><input type="checkbox" name="dkim_enabled" id="dkim_enabled"{DKIM_ENABLED}></td>
        </tr>
        <tr>
            <td>
                <label for="dkim_key_size">{TR_DKIM_KEY_SIZE}</label>
                <span class="icon i_help" title="{TR_DKIM_KEY_SIZE_HELP}">?</span>
            </td>
            <td>
                <select name="dkim_key_size" id="dkim_key_size">
                    <option value="1024"{KEY_1024}>1024</option>
                    <option value="2048"{KEY_2048}>2048</option>
                    <option value="4096"{KEY_4096}>4096</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>{TR_REGENERATE}</td>
            <td>
                <a class="icon i_reload" href="{REGENERATE_LINK}"
                   onclick="return confirm('{TR_REGENERATE_CONFIRM}');">{TR_REGENERATE}</a>
            </td>
        </tr>
        </tbody>
    </table>

    <table class="firstColFixed">
        <thead>
        <tr><th colspan="2">{TR_SPF_SECTION}</th></tr>
        </thead>
        <tbody>
        <tr>
            <td colspan="2"><div class="info">{TR_SPF_INTRO}</div></td>
        </tr>
        <tr>
            <td><label for="spf_mode">{TR_SPF_MODE}</label></td>
            <td>
                <select name="spf_mode" id="spf_mode">
                    <option value="off"{SPF_OFF}>{TR_SPF_MODE_OFF}</option>
                    <option value="guided"{SPF_GUIDED}>{TR_SPF_MODE_GUIDED}</option>
                    <option value="raw"{SPF_RAW_MODE}>{TR_SPF_MODE_RAW}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td><label for="spf_a">{TR_SPF_A}</label></td>
            <td><input type="checkbox" name="spf_a" id="spf_a"{SPF_A}></td>
        </tr>
        <tr>
            <td><label for="spf_mx">{TR_SPF_MX}</label></td>
            <td><input type="checkbox" name="spf_mx" id="spf_mx"{SPF_MX}></td>
        </tr>
        <tr>
            <td>
                <label for="spf_hosts">{TR_SPF_HOSTS}</label>
                <span class="icon i_help" title="{TR_SPF_HOSTS_HELP}">?</span>
            </td>
            <td><textarea name="spf_hosts" id="spf_hosts" rows="3" cols="40">{SPF_HOSTS}</textarea></td>
        </tr>
        <tr>
            <td>
                <label for="spf_includes">{TR_SPF_INCLUDES}</label>
                <span class="icon i_help" title="{TR_SPF_INCLUDES_HELP}">?</span>
            </td>
            <td><textarea name="spf_includes" id="spf_includes" rows="3" cols="40">{SPF_INCLUDES}</textarea></td>
        </tr>
        <tr>
            <td><label for="spf_qualifier">{TR_SPF_QUALIFIER}</label></td>
            <td>
                <select name="spf_qualifier" id="spf_qualifier">
                    <option value="-all"{SPF_FAIL}>{TR_SPF_FAIL}</option>
                    <option value="~all"{SPF_SOFTFAIL}>{TR_SPF_SOFTFAIL}</option>
                    <option value="?all"{SPF_NEUTRAL}>{TR_SPF_NEUTRAL}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>
                <label for="spf_redirect">{TR_SPF_REDIRECT}</label>
                <span class="icon i_help" title="{TR_SPF_REDIRECT_HELP}">?</span>
            </td>
            <td><input type="text" name="spf_redirect" id="spf_redirect" value="{SPF_REDIRECT}"></td>
        </tr>
        <tr>
            <td>
                <label for="spf_raw">{TR_SPF_RAW}</label>
                <span class="icon i_help" title="{TR_SPF_RAW_HELP}">?</span>
            </td>
            <td><textarea name="spf_raw" id="spf_raw" rows="3" cols="40">{SPF_RAW}</textarea></td>
        </tr>
        </tbody>
    </table>

    <table class="firstColFixed">
        <thead>
        <tr><th colspan="2">{TR_DMARC_SECTION}</th></tr>
        </thead>
        <tbody>
        <tr>
            <td colspan="2"><div class="info">{TR_DMARC_INTRO}</div></td>
        </tr>
        <tr>
            <td><label for="dmarc_enabled">{TR_DMARC_ENABLED}</label></td>
            <td><input type="checkbox" name="dmarc_enabled" id="dmarc_enabled"{DMARC_ENABLED}></td>
        </tr>
        <tr>
            <td><label for="dmarc_p">{TR_DMARC_P}</label></td>
            <td>
                <select name="dmarc_p" id="dmarc_p">
                    <option value="none"{DMARC_P_NONE}>{TR_DMARC_P_NONE}</option>
                    <option value="quarantine"{DMARC_P_QUAR}>{TR_DMARC_P_QUAR}</option>
                    <option value="reject"{DMARC_P_REJECT}>{TR_DMARC_P_REJECT}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td><label for="dmarc_sp">{TR_DMARC_SP}</label></td>
            <td>
                <select name="dmarc_sp" id="dmarc_sp">
                    <option value=""{DMARC_SP_SAME}>{TR_DMARC_SP_SAME}</option>
                    <option value="none"{DMARC_SP_NONE}>{TR_DMARC_P_NONE}</option>
                    <option value="quarantine"{DMARC_SP_QUAR}>{TR_DMARC_P_QUAR}</option>
                    <option value="reject"{DMARC_SP_REJECT}>{TR_DMARC_P_REJECT}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>
                <label for="dmarc_rua">{TR_DMARC_RUA}</label>
                <span class="icon i_help" title="{TR_DMARC_RUA_HELP}">?</span>
            </td>
            <td><input type="text" name="dmarc_rua" id="dmarc_rua" size="40" value="{DMARC_RUA}"></td>
        </tr>
        <tr>
            <td>
                <label for="dmarc_ruf">{TR_DMARC_RUF}</label>
                <span class="icon i_help" title="{TR_DMARC_RUF_HELP}">?</span>
            </td>
            <td><input type="text" name="dmarc_ruf" id="dmarc_ruf" size="40" value="{DMARC_RUF}"></td>
        </tr>
        <tr>
            <td>
                <label for="dmarc_adkim">{TR_DMARC_ADKIM}</label>
                <span class="icon i_help" title="{TR_DMARC_ALIGN_HELP}">?</span>
            </td>
            <td>
                <select name="dmarc_adkim" id="dmarc_adkim">
                    <option value="r"{DMARC_ADKIM_R}>{TR_DMARC_RELAXED}</option>
                    <option value="s"{DMARC_ADKIM_S}>{TR_DMARC_STRICT}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td><label for="dmarc_aspf">{TR_DMARC_ASPF}</label></td>
            <td>
                <select name="dmarc_aspf" id="dmarc_aspf">
                    <option value="r"{DMARC_ASPF_R}>{TR_DMARC_RELAXED}</option>
                    <option value="s"{DMARC_ASPF_S}>{TR_DMARC_STRICT}</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>
                <label for="dmarc_pct">{TR_DMARC_PCT}</label>
                <span class="icon i_help" title="{TR_DMARC_PCT_HELP}">?</span>
            </td>
            <td><input type="number" name="dmarc_pct" id="dmarc_pct" min="0" max="100" value="{DMARC_PCT}"></td>
        </tr>
        <tr>
            <td><label for="dmarc_ri">{TR_DMARC_RI}</label></td>
            <td><input type="number" name="dmarc_ri" id="dmarc_ri" min="3600" max="1209600" value="{DMARC_RI}"></td>
        </tr>
        </tbody>
    </table>

    <div class="buttons">
        <input name="submit" type="submit" value="{TR_UPDATE}">
        <a class="link_as_button" href="postfix_auth.php">{TR_CANCEL}</a>
    </div>
</form>

<table class="firstColFixed">
    <thead>
    <tr><th colspan="5">{TR_RECORDS_SECTION}</th></tr>
    </thead>
    <tbody>
    <tr><td colspan="5"><div class="info">{TR_RECORDS_INTRO}</div></td></tr>
    </tbody>
</table>

<!-- BDP: no_records_block -->
<div class="static_info">{TR_NO_RECORDS}</div>
<!-- EDP: no_records_block -->

<!-- BDP: record_list -->
<table class="firstColFixed datatable">
    <thead>
    <tr>
        <th>{TR_RECORD_KIND}</th>
        <th>{TR_RECORD_NAME}</th>
        <th>{TR_RECORD_TYPE}</th>
        <th>{TR_RECORD_VALUE}</th>
        <th>{TR_RECORD_STATE}</th>
    </tr>
    </thead>
    <tbody>
    <!-- BDP: record_item -->
    <tr>
        <td>{RECORD_KIND}</td>
        <td>{RECORD_NAME}</td>
        <td>TXT</td>
        <td style="word-break: break-all;">{RECORD_VALUE}</td>
        <td>
            <!-- BDP: record_state_block -->
            <div class="icon i_{RECORD_STATE_ICON}">{RECORD_STATE}</div>
            <!-- EDP: record_state_block -->
        </td>
    </tr>
    <!-- EDP: record_item -->
    </tbody>
</table>

<div class="buttons">
    <a class="link_as_button" href="{CHECK_LINK}">{TR_CHECK}</a>
</div>
<!-- EDP: record_list -->
