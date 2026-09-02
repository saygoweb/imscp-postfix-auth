<div class="info">{TR_INTRO}</div>

<!-- BDP: no_zones_block -->
<div class="static_info">{NO_ZONES}</div>
<!-- EDP: no_zones_block -->

<!-- BDP: zone_list -->
<table class="firstColFixed datatable">
    <thead>
    <tr>
        <th>{TR_STATUS}</th>
        <th>{TR_DOMAIN_NAME}</th>
        <th>{TR_ZONE_KIND}</th>
        <th>{TR_DKIM}</th>
        <th>{TR_SPF}</th>
        <th>{TR_DMARC}</th>
        <th>{TR_PUBLISH_DNS}</th>
        <th>{TR_NOTE}</th>
        <th>{TR_ACTION}</th>
    </tr>
    </thead>
    <tbody>
    <!-- BDP: zone_item -->
    <tr>
        <td><div class="icon i_{STATUS_ICON}">{STATUS}</div></td>
        <td>{DOMAIN_NAME}</td>
        <td>{ZONE_KIND}</td>
        <td>{DKIM}</td>
        <td>{SPF}</td>
        <td>{DMARC}</td>
        <td>{PUBLISH_DNS}</td>
        <td>{NOTE}</td>
        <td>
            <!-- BDP: zone_actions -->
            <a class="icon i_edit" href="{EDIT_LINK}" title="{TR_EDIT}">{TR_EDIT}</a>
            <!-- EDP: zone_actions -->
            <!-- BDP: zone_busy -->
            <span class="icon i_reload">{TR_BUSY}</span>
            <!-- EDP: zone_busy -->
        </td>
    </tr>
    <!-- EDP: zone_item -->
    </tbody>
</table>
<!-- EDP: zone_list -->
