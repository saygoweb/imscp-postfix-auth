<div class="info">{TR_INTRO}</div>

<!-- BDP: no_customers_block -->
<div class="static_info">{NO_CUSTOMERS}</div>
<!-- EDP: no_customers_block -->

<!-- BDP: customer_list -->
<table class="firstColFixed datatable">
    <thead>
    <tr>
        <th>{TR_CUSTOMER}</th>
        <th>{TR_ALLOWED}</th>
        <th>{TR_DKIM_COUNT}</th>
        <th>{TR_ACTION}</th>
    </tr>
    </thead>
    <tbody>
    <!-- BDP: customer_item -->
    <tr>
        <td>{CUSTOMER_NAME}</td>
        <td><div class="icon i_{ALLOWED_ICON}">{ALLOWED}</div></td>
        <td>{DKIM_COUNT}</td>
        <td>
            <a class="icon i_{PERM_ICON}" href="{PERM_LINK}" title="{PERM_LABEL}"
               onclick="{PERM_ONCLICK}">{PERM_LABEL}</a>
            <!-- BDP: bulk_actions -->
            <a class="icon i_ok" href="{ENABLE_LINK}" title="{TR_ENABLE_ALL}"
               onclick="return confirm('{TR_ENABLE_CONFIRM}');">{TR_ENABLE_ALL}</a>
            <a class="icon i_close" href="{DISABLE_LINK}" title="{TR_DISABLE_ALL}"
               onclick="return confirm('{TR_DISABLE_CONFIRM}');">{TR_DISABLE_ALL}</a>
            <!-- EDP: bulk_actions -->
        </td>
    </tr>
    <!-- EDP: customer_item -->
    </tbody>
</table>
<!-- EDP: customer_list -->
