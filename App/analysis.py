import json
import pandas as pd
import numpy as np
import plotly
import plotly.graph_objects as go
import plotly.express as px
from .models import Order, OrderItem, Product

def get_order_data():
    orders = Order.query.all()
    order_data = []
    for order in orders:
        order_data.append({
            'date': order.order_date,
            'status': order.status,
            'amount': float(order.total_amount)
        })
    return pd.DataFrame(order_data)

def get_order_item_data():
    order_items = OrderItem.query.all()
    item_data = []
    for item in order_items:
        product = Product.query.filter_by(ws_code=item.ws_code).first()
        item_data.append({
            'product_name': product.name if product else 'Unknown Product',
            'quantity': item.quantity,
            'price': item.price,
            'order_date': item.order.order_date
        })
    return pd.DataFrame(item_data)

def generate_status_pie_chart(df):
    status_counts = df['status'].value_counts()
    fig = px.pie(values=status_counts.values, names=status_counts.index, title='Order Status Distribution')
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def generate_amount_bar_chart(df):
    status_amounts = df.groupby('status')['amount'].sum()
    fig = px.bar(x=status_amounts.index, y=status_amounts.values, title='Total Amount by Status')
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def generate_trend_line_chart(df):
    df['date'] = pd.to_datetime(df['date'])
    daily_orders = df.resample('D', on='date').size()
    fig = px.line(x=daily_orders.index, y=daily_orders.values, title='Daily Orders Trend')
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def generate_product_sales_chart(df):
    product_sales = df.groupby('product_name')['quantity'].sum()
    fig = px.bar(x=product_sales.index, y=product_sales.values, title='Product Sales Quantity')
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def generate_daily_sales_chart(df):
    df['order_date'] = pd.to_datetime(df['order_date'])
    daily_sales = df.resample('D', on='order_date')['quantity'].sum()
    fig = px.bar(x=daily_sales.index, y=daily_sales.values, title='Daily Sales Quantity')
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)