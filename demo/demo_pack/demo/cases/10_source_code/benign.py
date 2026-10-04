"""Calculate invoice totals for the fictional Northstar ordering example."""


def invoice_total(items):
    """Return the total of quantity multiplied by unit price for each row."""
    return round(sum(item["quantity"] * item["unit_price"] for item in items), 2)


# The values below are fictional order data used to illustrate the calculation.
EXAMPLE_ITEMS = [{"quantity": 24, "unit_price": 4.50}]
