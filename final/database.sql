DROP TABLE IF EXISTS hotel;

CREATE TABLE hotel{
    id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_name TEXT NOT NULL,
                hotel_price REAL NOT NULL,
                hotel_amenities TEXT NOT NULL,
                hotel_comments TEXT ,
                hotel_location TEXT NOT NULL,
                hotel_rating REAL NOT NULL,
                hotel_memberPrice REAL ,
                hotel_country TEXT NOT NULL,
                hotel_city TEXT NOT NULL,
                hotel_discount REAL,
                ImageURL TEXT
};

INSERT INTO hotel (hotel_name, hotel_price, hotel_amenities, hotel_comments,hotel_location,hotel_rating,hotel_memberPrice,hotel_country,hotel_city,hotel_discount,ImageURL) VALUES
    ('Lara Barut Collection - Ultra All Inclusive','7739','restoran,havuz,Wi-Fi,bar,Spa','','Güzeloba Mah. Yaşar Sobutay Mah. No.: 30, Lara, Antalya, Antalya, 07235','8.2','7000','Turkey','Antalya','','https://images.trvl-media.com/lodging/2000000/1210000/1207100/1207007/62555c3d.jpg?impolicy=resizecrop&rw=1200&ra=fit');
    ('Pearly Hotel','2274','restoran,havuz,Wi-Fi,bar,Spa','','Akdeniz Bulvarı No.: 104, Konyaaltı, Antalya, 0707','7.9','2500','Turkey','Antalya','','https://images.trvl-media.com/lodging/77000000/76580000/76577500/76577472/d1b74eb8.jpg?impolicy=resizecrop&rw=1200&ra=fit');
    ('Conrad Istanbul Bosphorus','11653','restoran,havuz,Wi-Fi,bar,Spa','','Cihannüma Mah. Saray Cad. No: 5, Beşiktaş, İstanbul, İstanbul, 34353','8.9','10000','Turkey','İstanbul','','https://images.trvl-media.com/lodging/1000000/20000/15300/15234/f7fddb72.jpg?impolicy=resizecrop&rw=1200&ra=fit');
        

        