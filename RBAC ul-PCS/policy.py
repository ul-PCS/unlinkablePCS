from email import policy
import numpy as np

class Policy():
    def maker(self,n_R):
        F_lambda = np.random.randint(2, size=(n_R, n_R))
        return F_lambda
