const express = require('express');

//import Apollo server
const { ApolloServer } = require('apollo-server-express');

//import our typedefs
const { typeDefs, resolvers } = require('./schemas');
const db = require('./config/connection');

const PORT = process.env.PORT || 3001;
const app = express();

//create new Apollo server
const server = new ApolloServer({
  typeDefs,
  resolvers
});

//integrate our Apollo server with the Express application as middleware
server.applyMiddleware({ app });

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

db.once('open', () => {
  app.listen(PORT, () => {
    console.log(`API server running on port ${PORT}!`);
    console.log(`Use GraphQl at http://localhost:${PORT}${server.graphqlPath}`);
  });
});
