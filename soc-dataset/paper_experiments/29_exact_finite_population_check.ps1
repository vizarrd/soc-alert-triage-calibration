# Exact numerical check of the order-statistic rule for sampling WITHOUT replacement from a finite stream.
#
# Setting: a stream contains N attacks with distinct scores (ties only add slack). n of them are labelled,
# chosen uniformly at random without replacement. The rule picks the largest rank r with
#     P(Bin(n, 1-rho) >= r) >= 1 - delta            (equivalent to the Beta(r, n-r+1) cdf form), and uses the
# r-th smallest labelled attack score as threshold. True recall at that threshold is >= rho  iff at most
# floor((1-rho)*N) population attacks score strictly below the threshold, i.e. iff the r-th smallest sampled
# attack is among the K = floor((1-rho)*N) + 1 lowest population attacks, i.e. iff
#     Hypergeometric(population N, K "low" items, n draws) >= r .
# So the exact finite-population success probability is  P_hyp = P(Hyp(N, K, n) >= r).
# We compute it for all n in [n_min, 1000] (n <= N), rho in {0.80, 0.90, 0.95}, delta = 0.10, and
# N in {3426 (fewest attacks in any evaluated stream), 10000, 44524 (most)}, and report the minimum
# and where it occurs. The i.i.d. value P_iid = P(Bin(n, K/N) >= r) is computed for comparison.
Add-Type -TypeDefinition @"
using System;
public static class Check {
  static double[] lf;
  static void Init(int m) { lf = new double[m + 1]; for (int i = 2; i <= m; i++) lf[i] = lf[i - 1] + Math.Log(i); }
  static double LC(int n, int k) { return lf[n] - lf[k] - lf[n - k]; }
  static double HypPmf(int N, int K, int n, int x) {
    if (x < 0 || x > K || n - x < 0 || n - x > N - K) return 0.0;
    return Math.Exp(LC(K, x) + LC(N - K, n - x) - LC(N, n));
  }
  static double BinTail(int n, double p, int r) { // P(X >= r)
    double s = 0; for (int x = r; x <= n; x++) s += Math.Exp(LC(n, x) + x * Math.Log(p) + (n - x) * Math.Log(1 - p)); return s; }
  public static string Run() {
    Init(50000);
    double delta = 0.10; var sb = new System.Text.StringBuilder();
    double globalMin = 2.0; string where = "";
    foreach (double rho in new double[] { 0.80, 0.90, 0.95 }) {
      double alpha = 1 - rho; int nmin = (int)Math.Ceiling(Math.Log(delta) / Math.Log(rho));
      foreach (int N in new int[] { 3426, 10000, 44524 }) {
        int K = (int)Math.Floor(alpha * N) + 1; double minHyp = 2.0, minIid = 2.0; int argn = 0, argr = 0; int viol = 0, cnt = 0;
        for (int n = nmin; n <= 1000 && n <= N; n++) {
          int r = 0;
          for (int rr = 1; rr <= n; rr++) if (BinTail(n, alpha, rr) >= 1 - delta) r = rr; // largest feasible r
          if (r == 0) continue;
          double phyp = 0; int top = Math.Min(n, K); for (int x = r; x <= top; x++) phyp += HypPmf(N, K, n, x);
          double piid = BinTail(n, (double)K / N, r);
          cnt++; if (phyp < 1 - delta) viol++;
          if (phyp < minHyp) { minHyp = phyp; argn = n; argr = r; }
          if (piid < minIid) minIid = piid;
        }
        sb.AppendFormat("rho={0:F2} N={1,6} (K={2,5}): n in [{3},1000]: min exact finite-pop success = {4:F4} (at n={5}, r={6}); min iid-with-same-p = {7:F4}; settings with success < 0.90: {8}/{9}\n",
          rho, N, K, nmin, minHyp, argn, argr, minIid, viol, cnt);
        if (minHyp < globalMin) { globalMin = minHyp; where = "rho=" + rho + ", N=" + N + ", n=" + argn; }
      }
    }
    sb.AppendFormat("GLOBAL minimum exact finite-population success probability = {0:F4} at {1}\n", globalMin, where);
    return sb.ToString();
  }
}
"@
[Check]::Run()
